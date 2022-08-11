/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file relying_party.c
 * @author Antonio Marques from attester.c code written by Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2022-06-01
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include <arpa/inet.h>
#include <coap2/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tinydtls/session.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_dto.h"
#include "core/charra_helper.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "util/cbor_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"
#include "util/crypto_util.h"


#define CHARRA_UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* quit signal */
static bool quit = false;

/* logging */
#define LOG_NAME "relying_party"
coap_log_t coap_log_level = LOG_INFO;
// #define LOG_LEVEL_CBOR LOG_DEBUG
charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* config */
//static const char LISTEN_ADDRESS[] = "172.18.0.2";
char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = COAP_DEFAULT_PORT; // default port 5683
#define CBOR_ENCODER_BUFFER_LENGTH 20480	  // 20 KiB should be sufficient
bool use_ima_event_log = false;
char* ima_event_log_path =
	"/sys/kernel/security/ima/binary_runtime_measurements";
bool use_dtls_psk = false;
char* dtls_psk_key = "Charra DTLS Key";
char* dtls_psk_hint = "Charra Attester"; 	// REVER ESTE ITEM
// TODO allocate memory for CBOR buffer using malloc() since logs can be huge

// for DTLS-RPK
bool use_dtls_rpk = false;
char* dtls_rpk_private_key_path = "keys/rparty.der";
// char* dtls_rpk_public_key_path = "keys/attester.pub.der";
char* dtls_rpk_public_key_path = "keys/rparty.pub.der";
char* verifier_public_key_path = "keys/verifier.pub.der";
char* dtls_rpk_peer_public_key_path = "keys/attester.pub.der";
bool dtls_rpk_verify_peer_public_key = true;

/**
 * @brief SIGINT handler: set quit to 1 for graceful termination.
 *
 * @param signum the signal number.
 */
static void handle_sigint(int signum);


static void coap_attest_result_handler();


/* --- main --------------------------------------------------------------- */

int main(int argc, char** argv) {
	int result = EXIT_FAILURE;

	/* handle SIGINT */
	signal(SIGINT, handle_sigint);

	/* set CHARRA and libcoap log levels */
	charra_log_set_level(charra_log_level);
	coap_set_log_level(coap_log_level);

	/* check environment variables */
	charra_log_level_from_str(
		(const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);
	charra_coap_log_level_from_str(
		(const char*)getenv("LOG_LEVEL_COAP"), &coap_log_level);

	/* initialize structures to pass to the CLI parser */
	cli_config cli_config = {
		.caller = RPARTY,
		.common_config =
			{
				.charra_log_level = &charra_log_level,
				.coap_log_level = &coap_log_level,
				.port = &port,
				.use_dtls_psk = &use_dtls_psk,
				.dtls_psk_key = &dtls_psk_key,
				.use_dtls_rpk = &use_dtls_rpk,
				.dtls_rpk_private_key_path = &dtls_rpk_private_key_path,
				.dtls_rpk_public_key_path = &dtls_rpk_public_key_path,
				.dtls_rpk_peer_public_key_path = &dtls_rpk_peer_public_key_path,
				.dtls_rpk_verify_peer_public_key =
					&dtls_rpk_verify_peer_public_key,
			},
		.rparty_config =
			{
				.dtls_psk_hint = &dtls_psk_hint,
			},
	};
	

	/* parse CLI arguments */
	
	if ((result = parse_command_line_arguments(argc, argv, &cli_config)) != 0) {
		// 1 means help message is displayed, -1 means error
		return (result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	
	
	/* set CHARRA and libcoap log levels */
	charra_log_set_level(charra_log_level);
	coap_set_log_level(coap_log_level);

	charra_log_debug("[" LOG_NAME "] Relying Party Configuration:");
	charra_log_debug("[" LOG_NAME "]     Used local IP: %s", LISTEN_ADDRESS);
	charra_log_debug("[" LOG_NAME "]     Used local port: %d", port);
	charra_log_debug("[" LOG_NAME "]     DTLS-PSK enabled: %s",
		(use_dtls_psk == true) ? "true" : "false");
	if (use_dtls_psk) {
		charra_log_debug("[" LOG_NAME "]         Pre-shared key: '%s'",
			dtls_psk_key);
		charra_log_debug(
			"[" LOG_NAME "]         Hint: '%s'", dtls_psk_hint);
	}
	charra_log_debug("[" LOG_NAME "]     DTLS-RPK enabled: %s",
		(use_dtls_rpk == true) ? "true" : "false");
	if (use_dtls_rpk) {
		charra_log_debug("[" LOG_NAME
						 "]         Private key path: '%s'",
			dtls_rpk_private_key_path);
		charra_log_debug("[" LOG_NAME
						 "]         Public key path: '%s'",
			dtls_rpk_public_key_path);
		charra_log_debug("[" LOG_NAME
						 "]         Peers' public key path: '%s'",
			dtls_rpk_peer_public_key_path);
	}

	/* set varaibles here such that they are valid in case of an 'goto error' */
	coap_context_t* coap_context = NULL;
	coap_endpoint_t* coap_endpoint = NULL;

	if (use_dtls_psk && use_dtls_rpk) {
		charra_log_error(
			"[" LOG_NAME "] Configuration enables both DTSL with PSK "
			"and DTSL with PKI. Aborting!");
		goto error;
	}

	if (use_dtls_psk || use_dtls_rpk) {
		// print TLS version when in debug mode
		coap_show_tls_version(LOG_DEBUG);
	}

	if ((use_dtls_psk || use_dtls_psk) && !coap_dtls_is_supported()) {
		charra_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
						 "configuration enables DTLS. Aborting!");
		goto error;
	}

	charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
	if ((coap_context = charra_coap_new_context(true)) == NULL) {
		charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
		goto error;
	}

	if (use_dtls_psk) {
		charra_log_info(
			"[" LOG_NAME "] Creating CoAP server endpoint using DTLS-PSK.");
		if (!coap_context_set_psk(coap_context, dtls_psk_hint,
				(uint8_t*)dtls_psk_key, strlen(dtls_psk_key))) {
			charra_log_error(
				"[" LOG_NAME "] Error while configuring CoAP to use DTLS-PSK.");
			goto error;
		}

		if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
				 LISTEN_ADDRESS, port, COAP_PROTO_DTLS)) == NULL) {
			charra_log_error(
				"[" LOG_NAME
				"] Cannot create CoAP server endpoint based on DTLS-PSK.\n");
			goto error;
		}
	} else if (use_dtls_rpk) {
		charra_log_info(
			"[" LOG_NAME "] Creating CoAP server endpoint using DTLS-RPK.");
		coap_dtls_pki_t dtls_pki = {0};

		CHARRA_RC rc = charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
			dtls_rpk_private_key_path, dtls_rpk_public_key_path,
			dtls_rpk_peer_public_key_path, dtls_rpk_verify_peer_public_key);
		if (rc != CHARRA_RC_SUCCESS) {
			charra_log_error(
				"[" LOG_NAME "] Error while setting up DTLS-RPK structure.");
			goto error;
		}

		if (!coap_context_set_pki(coap_context, &dtls_pki)) {
			charra_log_error(
				"[" LOG_NAME "] Error while configuring CoAP to use DTLS-RPK.");
			goto error;
		}

		if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
				 LISTEN_ADDRESS, port, COAP_PROTO_DTLS)) == NULL) {
			charra_log_error(
				"[" LOG_NAME
				"] Cannot create CoAP server endpoint based on DTLS-RPK.\n");
			goto error;
		}
	} else {    
		charra_log_info(
			"[" LOG_NAME "] Creating CoAP server endpoint using UDP.");
		if ((coap_endpoint = charra_coap_new_endpoint(
				 coap_context, LISTEN_ADDRESS, port, COAP_PROTO_UDP)) == NULL) {
			charra_log_error(
				"[" LOG_NAME
				"] Cannot create CoAP server endpoint based on UDP.\n");
			goto error;
		}
	}

	/* New resource and handler */
	charra_log_info("[" LOG_NAME "] Registering CoAP [relying_party] resources.");
	charra_coap_add_resource(
 	 	coap_context, COAP_REQUEST_FETCH, "attRes", coap_attest_result_handler);


	/* enter main loop */
	charra_log_debug("[" LOG_NAME "] Entering main loop.");
	while (!quit) {
		/* process CoAP I/O */
		if (coap_io_process(coap_context, COAP_IO_WAIT) == -1) {
			charra_log_error(
				"[" LOG_NAME "] Error during CoAP I/O processing.");
			goto error;
		} 
	}

	charra_log_info("[" LOG_NAME "] Finished.");
	result = EXIT_SUCCESS;
	goto finish;

error:
	result = EXIT_FAILURE;

finish:
    // result = 0;
	/* free CoAP memory */
	charra_free_and_null_ex(coap_endpoint, coap_free_endpoint);
	charra_free_and_null_ex(coap_context, coap_free_context);
	coap_cleanup();

	return result;
}

/* --- function definitions ----------------------------------------------- */

static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }

static void coap_attest_result_handler(struct coap_context_t* context CHARRA_UNUSED,
	coap_session_t* session CHARRA_UNUSED, coap_pdu_t* sent CHARRA_UNUSED,
	coap_pdu_t* in, const coap_mid_t mid CHARRA_UNUSED) {

	/* --- receive incoming data --- */
	charra_log_info("[" LOG_NAME "] +-----------------------------------+");
	charra_log_info("[" LOG_NAME "] |    ATTESTATION RESULT RECEIVED    |");
	charra_log_info("[" LOG_NAME "] +-----------------------------------+");

	charra_log_info(
		"[" LOG_NAME "] Resource '%s': Received message.", "attRes");
	
	coap_show_pdu(LOG_DEBUG, in);


	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
	int coap_r = 0;

	/* get data */
	size_t data_len = 0;
	const uint8_t* data = NULL;
	size_t data_offset = 0;
	size_t data_total_len = 0;

	if ((coap_r = coap_get_data_large(
			 in, &data_len, &data, &data_offset, &data_total_len)) == 0) {
		charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
		// goto error;
	} else {
		charra_log_info(
			"[" LOG_NAME "] Received data of length %zu.", data_len);
		charra_log_info("[" LOG_NAME "] Received data of total length %zu.",
			data_total_len);
	}


	/* unmarshal data */
	charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
	msg_attestation_appraise_result_dto att_result = {0};
	if ((charra_r = charra_unmarshal_attestation_passport(
			 data_len, data, &att_result)) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
	} else {
		charra_log_info("[" LOG_NAME "] Attestation Result Unmarshelled");
	}

	charra_log_debug("[" LOG_NAME "]     data_len %d", data_len); 
	charra_log_debug("[" LOG_NAME "]     data = < %s >", att_result.attestation_result_data); 
	charra_log_debug("[" LOG_NAME "]     signature_len %d", att_result.attestation_signature_len ); 
	charra_log_info("[" LOG_NAME "] Public key path [ %s ]", verifier_public_key_path ); 

 	if ((charra_verify_att_result(verifier_public_key_path, att_result.attestation_result_data, 
		att_result.attestation_signature, att_result.attestation_signature_len) !=0)) {
		charra_log_error("[" LOG_NAME "] error verifing signature attestation result.");
	} else {
		charra_log_info("[" LOG_NAME "] +-----------------------------------+");
		charra_log_info("[" LOG_NAME "] |      PASSPORT MODEL VALIDATED     |");
		charra_log_info("[" LOG_NAME "] +-----------------------------------+");
	}

	// quit = true;

}



