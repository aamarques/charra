/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file crypto_util.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief Provides IMA related crypto functions.
 * @version 0.1
 * @date 2019-12-22
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "crypto_util.h"

#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

// Includes to sign
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../util/charra_util.h"
#include "../util/io_util.h"

#define LOG_NAME "crypto_util"

/* hashing functions */

CHARRA_RC hash_sha1(const size_t data_len, const uint8_t* const data,
	uint8_t digest[TPM2_SHA1_DIGEST_SIZE]) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;

	/* init */
	mbedtls_sha1_context ctx = {0};
	mbedtls_sha1_init(&ctx);

	/* hash */
	if ((mbedtls_sha1_starts_ret(&ctx)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	if ((mbedtls_sha1_update_ret(&ctx, data, data_len)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	if ((mbedtls_sha1_finish_ret(&ctx, digest)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	/* free */
	mbedtls_sha1_free(&ctx);

	return r;
}

CHARRA_RC hash_sha256(const size_t data_len, const uint8_t* const data,
	uint8_t digest[TPM2_SHA256_DIGEST_SIZE]) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;

	/* init */
	mbedtls_sha256_context ctx = {0};
	mbedtls_sha256_init(&ctx);

	/* hash */
	if ((mbedtls_sha256_starts_ret(&ctx, 0)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	if ((mbedtls_sha256_update_ret(&ctx, data, data_len)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	if ((mbedtls_sha256_finish_ret(&ctx, digest)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	/* free */
	mbedtls_sha256_free(&ctx);

	return r;
}

CHARRA_RC hash_sha256_array(uint8_t* data[TPM2_SHA256_DIGEST_SIZE],
	const size_t data_len, uint8_t digest[TPM2_SHA256_DIGEST_SIZE]) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;

	/* init */
	mbedtls_sha256_context ctx = {0};
	mbedtls_sha256_init(&ctx);

	/* hash */
	if ((mbedtls_sha256_starts_ret(&ctx, 0)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	for (size_t i = 0; i < data_len; ++i) {
		if ((mbedtls_sha256_update_ret(
				&ctx, data[i], TPM2_SHA256_DIGEST_SIZE)) != 0) {
			r = CHARRA_RC_CRYPTO_ERROR;
			goto error;
		}
	}

	if ((mbedtls_sha256_finish_ret(&ctx, digest)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	/* free */
	mbedtls_sha256_free(&ctx);

	return r;
}

CHARRA_RC hash_sha512(const size_t data_len, const uint8_t* const data,
	uint8_t digest[TPM2_SM3_256_DIGEST_SIZE]) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;

	/* init */
	mbedtls_sha512_context ctx = {0};
	mbedtls_sha512_init(&ctx);

	/* hash */
	if ((mbedtls_sha512_starts_ret(&ctx, 0) /* 0 = SHA512 */
			) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	if ((mbedtls_sha512_update_ret(&ctx, data, data_len)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	if ((mbedtls_sha512_finish_ret(&ctx, digest)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	/* free */
	mbedtls_sha512_free(&ctx);

	return r;
}

CHARRA_RC charra_crypto_hash(mbedtls_md_type_t hash_algo,
	const uint8_t* const data, const size_t data_len,
	uint8_t digest[MBEDTLS_MD_MAX_SIZE]) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;

	/* init */
	const mbedtls_md_info_t* hash_info = mbedtls_md_info_from_type(hash_algo);
	mbedtls_md_context_t ctx = {0};
	if ((mbedtls_md_init_ctx(&ctx, hash_info)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	/* hash */
	if ((mbedtls_md_starts(&ctx)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	if ((mbedtls_md_update(&ctx, data, data_len)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	if ((mbedtls_md_finish(&ctx, digest)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	/* free */
	mbedtls_md_free(&ctx);

	return r;
}

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
	const TPM2B_PUBLIC* tpm_rsa_pub_key,
	mbedtls_rsa_context* mbedtls_rsa_pub_key) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;
	int mbedtls_r = 0;

	/* construct a RSA public key from modulus and exponent */
	mbedtls_mpi n = {0}; /* modulus */
	mbedtls_mpi e = {0}; /* exponent */

	/* init mbedTLS structures */
	mbedtls_rsa_init(mbedtls_rsa_pub_key, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_mpi_init(&n);
	mbedtls_mpi_init(&e);

	if ((mbedtls_r = mbedtls_mpi_read_binary(&n,
			 (const unsigned char*)
				 tpm_rsa_pub_key->publicArea.unique.rsa.buffer,
			 (size_t)tpm_rsa_pub_key->publicArea.unique.rsa.size)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		printf("Error mbedtls_mpi_read_binary\n");
		goto error;
	}

	/* set exponent from TPM public key (if 0 set it to 65537) */
	{
		uint32_t exp = 65537; /* set default exponent */
		if (tpm_rsa_pub_key->publicArea.parameters.rsaDetail.exponent != 0) {
			exp = tpm_rsa_pub_key->publicArea.parameters.rsaDetail.exponent;
		}

		if ((mbedtls_r = mbedtls_mpi_lset(&e, (mbedtls_mpi_sint)exp)) != 0) {
			r = CHARRA_RC_CRYPTO_ERROR;
			printf("Error mbedtls_mpi_lset\n");
			goto error;
		}
	}

	if ((mbedtls_r = mbedtls_rsa_import(
			 mbedtls_rsa_pub_key, &n, NULL, NULL, NULL, &e)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		printf("Error mbedtls_rsa_import\n");
		goto error;
	}

	if ((mbedtls_r = mbedtls_rsa_complete(mbedtls_rsa_pub_key)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		printf("Error mbedtls_rsa_complete\n");
		goto error;
	}

	if ((mbedtls_r = mbedtls_rsa_check_pubkey(mbedtls_rsa_pub_key)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		printf("Error mbedtls_rsa_check_pubkey\n");
		goto error;
	}

	/* cleanup */
	mbedtls_mpi_free(&n);
	mbedtls_mpi_free(&e);

	return CHARRA_RC_SUCCESS;

error:
	/* cleanup */
	mbedtls_rsa_free(mbedtls_rsa_pub_key);
	mbedtls_mpi_free(&n);
	mbedtls_mpi_free(&e);

	return r;
}

CHARRA_RC charra_crypto_rsa_verify_signature_hashed(
	mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
	const unsigned char* data_digest, const unsigned char* signature) {
	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
	int mbedtls_r = 0;

	/* verify signature */
	if ((mbedtls_r = mbedtls_rsa_rsassa_pss_verify(mbedtls_rsa_pub_key, NULL,
			 NULL, MBEDTLS_RSA_PUBLIC, hash_algo, 0, data_digest, signature)) !=
		0) {
		charra_r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	return charra_r;
}

CHARRA_RC charra_crypto_rsa_verify_signature(
	mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
	const unsigned char* data, size_t data_len,
	const unsigned char* signature) {
	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

	/* hash data */
	uint8_t data_digest[MBEDTLS_MD_MAX_SIZE] = {0};
	if ((charra_r = charra_crypto_hash(
			 hash_algo, data, data_len, data_digest)) != CHARRA_RC_SUCCESS) {
		goto error;
	}

	/* verify signature */
	if ((charra_r = charra_crypto_rsa_verify_signature_hashed(
			 mbedtls_rsa_pub_key, hash_algo, data_digest, signature)) != 0) {
		charra_r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	return charra_r;
}

CHARRA_RC compute_and_check_PCR_digest(uint8_t** pcr_values,
	uint32_t pcr_values_len, const TPMS_ATTEST* const attest_struct) {
	uint8_t pcr_composite_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
	/* TODO use crypto-agile (generic) version
	 * charra_compute_pcr_composite_digest_from_ptr_array(), once
	 * implemented, instead of hash_sha256_array() (then maybe remove
	 * hash_sha256_array() function) */
	CHARRA_RC charra_r =
		hash_sha256_array(pcr_values, pcr_values_len, pcr_composite_digest);
	if (charra_r != CHARRA_RC_SUCCESS) {
		return CHARRA_RC_ERROR;
	}
	bool matching = charra_verify_tpm2_quote_pcr_composite_digest(
		attest_struct, pcr_composite_digest, TPM2_SHA256_DIGEST_SIZE);
	charra_print_hex(CHARRA_LOG_DEBUG, sizeof(pcr_composite_digest),
		pcr_composite_digest,
		"                                              0x", "\n", false);
	if (matching) {
		return CHARRA_RC_SUCCESS;
	} else {
		return CHARRA_RC_NO_MATCH;
	}
}


CHARRA_RC charra_sign_att_result(char* peer_private_key_path, 
	unsigned char* attestationResult, unsigned char signature[], size_t* sig_size)
{

// From: Verifier
// Send: path_to_verifier_pk, attestationResult
// Return: Signature, length

    mbedtls_pk_context peer_private_key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&peer_private_key);

    int ret = 1;
    int exit_code = CHARRA_RC_ERROR;
    unsigned char hash[32];
    unsigned char sig_buffer[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
	size_t sig_buffer_len = 0;
    // const unsigned char (*att_result)[] = attestationResult;
	const unsigned char *att_result = attestationResult;
    const char *pers = "mbedtls_pk_sign";
    size_t att_result_len = sizeof(attestationResult);
    
	charra_log_info("[" LOG_NAME "] Received attestationResult is: [ %s ]", attestationResult);
    charra_log_info("[" LOG_NAME "] Seeding the random number generator...");

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        charra_log_info("[" LOG_NAME "] mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret );
        goto exit;
    }

    charra_log_info("[" LOG_NAME "] Reading private key from '%s'", peer_private_key_path );

	if( ( ret = mbedtls_pk_parse_keyfile( &peer_private_key, peer_private_key_path, "" ) ) != 0 )
    {
        charra_log_info("[" LOG_NAME "] Could not read '%s'\n", peer_private_key_path );
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the signature of the hash.
     */
    charra_log_info("[" LOG_NAME "] Generating the SHA-256 signature");

	/* hash data */
	if ((ret = charra_crypto_hash(
			 MBEDTLS_MD_SHA256, att_result, att_result_len, hash)) != CHARRA_RC_SUCCESS) {
		goto exit;
	}

	/* sign data */
     if( ( ret = mbedtls_pk_sign( &peer_private_key, MBEDTLS_MD_SHA256,
	 		hash, 0, sig_buffer, &sig_buffer_len, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )	{
         charra_log_info("[" LOG_NAME "] mbedtls_pk_sign returned -0x%04x\n", (unsigned int) -ret );
         goto exit;
    }

	memcpy(signature, sig_buffer, sig_buffer_len);
	*sig_size = sig_buffer_len;
	// *sig_size = sizeof(sig_buffer);

	charra_log_debug("[" LOG_NAME "] att_result is: [ %s ]", att_result);
	charra_log_debug("[" LOG_NAME "] att_result_len is: [ %d ]", att_result_len);
    charra_log_debug("[" LOG_NAME "] Generated signature lenght: %d - %d", sig_buffer_len, sizeof(sig_buffer));

    charra_log_debug("[" LOG_NAME "] Generated HASH of lenght: %d", sizeof(hash));
	charra_print_hex(CHARRA_LOG_INFO, sizeof(hash), hash,
		"  hash generated                                         0x", "\n", false);

    charra_log_debug("[" LOG_NAME "] Generated signature total of lenght = %d", sizeof(sig_buffer));
	charra_print_hex(CHARRA_LOG_INFO,  sig_buffer_len, signature,
		"  signature generated                                    0x", "\n", false);

    exit_code = CHARRA_RC_SUCCESS;

exit:
    mbedtls_pk_free( &peer_private_key);
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return exit_code;
}

CHARRA_RC charra_verify_att_result(char* peer_public_key_path, 
	unsigned char* attestationResult, unsigned char signature[], size_t sig_size)
{

/// Verifying
// From RP:
// send: Path_to_verifier_pub_key, attestationResult, signature
// return: SUCESS or FAIL

	int ret = 1;
    int exit_code = CHARRA_RC_ERROR;

	unsigned char hash[32];
    const unsigned char *att_result = attestationResult;
    size_t att_result_len = sizeof(att_result);

    mbedtls_pk_context peer_public_key;  
    mbedtls_pk_init (&peer_public_key);

	charra_log_info("[" LOG_NAME "] Recieved attestationResult:  [ %s ]", attestationResult);
	charra_log_info("[" LOG_NAME "] Recieved attestationResult:  [ %d ]", sig_size);
 	charra_log_info("[" LOG_NAME "] Reading public key from '%s'", peer_public_key_path );

    if( ( ret = mbedtls_pk_parse_public_keyfile( &peer_public_key, peer_public_key_path) ) != 0 )
    {
        charra_log_error("[" LOG_NAME "] Could not read '%s'\n", peer_public_key_path );
        goto exit;
    }

   
	/* hash data */
	if ((ret = charra_crypto_hash(
			 MBEDTLS_MD_SHA256, att_result, att_result_len, hash)) != CHARRA_RC_SUCCESS) {
		goto exit;
	}
	
	charra_log_debug("[" LOG_NAME "] Generated HASH of lenght %d:", sizeof(hash));
	charra_log_debug("[" LOG_NAME "] Generated sig_size of lenght %ld:", sig_size);

	charra_print_hex(CHARRA_LOG_INFO, sizeof(hash), hash,
		" hash regenerated                                        0x", "\n", false);


	charra_print_hex(CHARRA_LOG_INFO, sig_size, signature,
		" signature to verify                                     0x", "\n", false);


    if( ( ret = mbedtls_pk_verify( &peer_public_key, MBEDTLS_MD_SHA256, hash, 0,
                           signature, sig_size ) ) != CHARRA_RC_SUCCESS )
    {
         charra_log_error("[" LOG_NAME "] FAILED: mbedtls_pbk_verify returned -0x%04x", (unsigned int) -ret );
		 mbedtls_strerror( ret, (char *) signature, 1024 );
         charra_log_error("[" LOG_NAME "] Last error was: %s", signature );
        goto exit;
    }


    charra_log_info("[" LOG_NAME "] Signature Confirmed!");
    exit_code = CHARRA_RC_SUCCESS;

exit:
    mbedtls_pk_free(&peer_public_key);

    return  exit_code;
}