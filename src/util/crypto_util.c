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


CHARRA_RC charra_sign_att_result()
	// char signature, size_t olen)
{

// From: Verifier
// Send: path_to_verifier_pk, attestationResult
// Return: Signature, length

    int ret = 1;
    int exit_code = CHARRA_RC_ERROR;

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    unsigned char hash[32];
	unsigned char hash_v[32];
    unsigned char buf[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    const unsigned char text_to_sign[] = "text";
    const char *pers = "mbedtls_pk_sign";
    size_t olen = 0;
	char* peer_private_key_path = "keys/verifier.der";
	char* peer_public_key_path = "keys/verifier.pub.der";
    size_t ilen = sizeof(text_to_sign);

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_pk_init( &pk );
    
    charra_log_info("[" LOG_NAME "] Seeding the random number generator... ");

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        charra_log_info("[" LOG_NAME "] mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret );
        goto exit;
    }

    charra_log_info("[" LOG_NAME "] Reading private key from '%s'", peer_private_key_path );

	if( ( ret = mbedtls_pk_parse_keyfile( &pk, peer_private_key_path, "" ) ) != 0 )
    {
        charra_log_info("[" LOG_NAME "] Could not read '%s'\n", peer_private_key_path );
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the signature of the hash.
     */
    charra_log_info("[" LOG_NAME "] Generating the SHA-256 signature");

    if( ( ret = mbedtls_md( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), text_to_sign, ilen, hash ) ) != 0 )
    {
        charra_log_info("[" LOG_NAME "] Could read %s", text_to_sign );
        goto exit;
    }	

	
     if( ( ret = mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256, hash, 0, buf, &olen, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )								 
    {
         charra_log_info("[" LOG_NAME "] mbedtls_pk_sign returned -0x%04x\n", (unsigned int) -ret );
         goto exit;
    }

//// OKAY 
    charra_log_debug("[" LOG_NAME "] Generated signature lenght %d:", olen);
    charra_log_debug("[" LOG_NAME "] Generated HASH of lenght %d:", sizeof(hash));
	charra_print_hex(CHARRA_LOG_INFO, sizeof(hash), hash,
		"                                                         0x", "\n", false);

    charra_log_debug("[" LOG_NAME "] Generated signature total of lenght = %d", sizeof(buf));
	charra_print_hex(CHARRA_LOG_INFO, sizeof(buf), buf,
		"                                                         0x", "\n", false);


//// Verifying
// From RP:
// send: Path_to_verifier_pub_key, attestationResult, signature
// return: SUCESS or FAIL

    // mbedtls_pk_context pbk;
 	// mbedtls_pk_init( &pbk );

    // if( ( ret = mbedtls_pk_parse_public_keyfile( &pbk, peer_public_key_path) ) != 0 )
    // {
    //     charra_log_info("[" LOG_NAME "] Could not read '%s'\n", peer_public_key_path );
    //     goto exit;
    // }

	// if( ( ret = mbedtls_md(
	// 	        mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), 
	// 			text_to_sign, ilen, hash_v ) ) != 0 )
	// 	{
	// 		charra_log_info("[" LOG_NAME "] Could read %s", text_to_sign );
	// 		goto exit;
	// 	}	

    // charra_log_debug("[" LOG_NAME "] Generated HASH of lenght %d:", sizeof(hash_v));
	// charra_print_hex(CHARRA_LOG_INFO, sizeof(hash_v), hash_v,
	// 	"                                                         0x", "\n", false);


    // if( ( ret = mbedtls_pk_verify( &pbk, MBEDTLS_MD_SHA256, hash_v, 0,
    //                        buf, olen ) ) != 0 )
    // {
    //     mbedtls_printf( " failed\n  ! mbedtls_pk_verify returned -0x%04x\n", (unsigned int) -ret );
    //     goto exit;
    // }

    //  charra_log_info("[" LOG_NAME "] Signature is valid)" );


    exit_code = CHARRA_RC_SUCCESS;
	return exit_code;

exit:
    mbedtls_pk_free( &pk );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    // mbedtls_exit( exit_code );
};
