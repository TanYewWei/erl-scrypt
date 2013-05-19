/*
 * Authored by Yew-wei Tan on 13 May 2013
 *
 * scrypt library provided by Colin Percival. See Copyright below
 */

/*-
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <erl_nif.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/scrypt_platform.h"
#include "lib/scryptenc_cpuperf.h"
#include "lib/crypto_scrypt.h"
#include "lib/crypto_aesctr.h"
#include "lib/params.h"
#include "lib/sha256.h"
#include "lib/memlimit.h"
#include "lib/sysendian.h"
#include "lib/warn.h"

#define HASH_SIZE 96

typedef struct scrypt_params {
    uint8_t * passwd;
    size_t passwdlen;
    unsigned long maxmem;
    double maxmemfrac;
    double maxtime;
} scrypt_params;

ERL_NIF_TERM
basic_error(ErlNifEnv * env, char * reason)
{
    return enif_make_tuple2( env, 
                             enif_make_atom(env, "error"),
                             enif_make_atom(env, reason));
}

int 
hash_worker( uint8_t header[96],
             uint8_t dk[64],
             const uint8_t * passwd,
             size_t passwdlen,
             size_t maxmem,
             double maxmemfrac,
             double maxtime ) 
{        
    uint8_t salt[32];
	uint8_t hbuf[32];
    int logN;
    uint64_t N;
    uint32_t r;
    uint32_t p; 
    SHA256_CTX ctx;
    uint8_t * key_hmac = &dk[32];
    HMAC_SHA256_CTX hctx;
    int rc;

    /* Calculate parameters from options */
    if ((rc = pickparams(maxmem, maxmemfrac, maxtime, &logN, &r, &p) != 0))
        return (rc);
    N = (uint64_t)(1) << logN;
    //printf("N, r, p: %llu %u %u \n", N, r, p);

    /* Generate salt */
    if ((rc = getsalt(salt)) != 0)
        return (rc); 

    /* Generate the derived keys. */
    if (crypto_scrypt(passwd, passwdlen, salt, 32, N, r, p, dk, 64))
		return (3);

    /* Construct the file header. */
    memcpy(header, "scrypt", 6);
    header[6] = 0;
    header[7] = logN;
    be32enc(&header[8], r);
    be32enc(&header[12], p);
    memcpy(&header[16], salt, 32);

    /* Add header checksum. */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, header, 48);
    SHA256_Final(hbuf, &ctx);
    memcpy(&header[48], hbuf, 16);

    /* Add header signature (used for verifying password). */
    HMAC_SHA256_Init(&hctx, key_hmac, 32);
    HMAC_SHA256_Update(&hctx, header, 64);
    HMAC_SHA256_Final(hbuf, &hctx);
    memcpy(&header[64], hbuf, 32);

    return (0);
}

int 
verify_worker( const uint8_t header[96],
               uint8_t dk[64],
               const uint8_t * passwd,
               size_t passwdlen,
               size_t maxmem,
               double maxmemfrac,
               double maxtime ) 
{
    uint8_t salt[32];
	uint8_t hbuf[32];
	int logN;
	uint32_t r;
	uint32_t p;
	uint64_t N;
	SHA256_CTX ctx;
	uint8_t * key_hmac = &dk[32];
	HMAC_SHA256_CTX hctx;
	int rc;

	/* Parse N, r, p, salt. */
	logN = header[7];
    N = (uint64_t)(1) << logN;
	r = be32dec(&header[8]);
	p = be32dec(&header[12]);
	memcpy(salt, &header[16], 32);
    //printf("N, r, p: %llu %u %u \n", N, r, p);

	/* Verify header checksum. */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, header, 48);
	SHA256_Final(hbuf, &ctx);
	if (memcmp(&header[48], hbuf, 16))
		return (7);

	/*
	 * Check whether the provided parameters are valid and whether the
	 * key derivation function can be computed within the allowed memory
	 * and CPU time.
	 */
	if ((rc = checkparams(maxmem, maxmemfrac, maxtime, logN, r, p)) != 0) 
		return (rc);

	/* Compute the derived keys. */	
	if (crypto_scrypt(passwd, passwdlen, salt, 32, N, r, p, dk, 64))
		return (3);

	/* Check header signature (i.e., verify password). */
	HMAC_SHA256_Init(&hctx, key_hmac, 32);
	HMAC_SHA256_Update(&hctx, header, 64);
	HMAC_SHA256_Final(hbuf, &hctx);

    if (memcmp(hbuf, &header[64], 32)) // Bad password
		return (11);
    else
        return (0);
}

/* ----------------------------------------------------------------------
 * ERLANG NIF FUNCTIONS
 * ---------------------------------------------------------------------- */

scrypt_params *
parse_options(ErlNifEnv * env, const ERL_NIF_TERM argv[]) 
{
    scrypt_params * acc = malloc(sizeof(struct scrypt_params));

    ErlNifBinary pass_bin;    
    if (!enif_inspect_iolist_as_binary(env, argv[0], &pass_bin))
		return NULL;
    acc->passwd = (uint8_t *)pass_bin.data;
    acc->passwdlen = (size_t)pass_bin.size;

    if (!enif_get_ulong(env, argv[1], &acc->maxmem))
        return NULL;
    if (!enif_get_double(env, argv[2], &acc->maxmemfrac))
		return NULL;
    if (!enif_get_double(env, argv[3], &acc->maxtime))
		return NULL;

    return acc;
}

/*
 * Implementation copied largely from lib/scryptenc/scryptenc.c
 */
static ERL_NIF_TERM
hash(ErlNifEnv * env, int argc, const ERL_NIF_TERM argv[])
{   
    /* Get Options */
    scrypt_params * options = parse_options( env, argv ); 
    uint8_t * passwd = options->passwd;
    size_t passwdlen = options->passwdlen;
    size_t maxmem = options->maxmem;
    double maxmemfrac = options->maxmemfrac;
    double maxtime = options->maxtime;        

    /* Make Hash */
    uint8_t hash[ HASH_SIZE ];
    uint8_t dk[64];
    if (hash_worker( hash, 
                     dk,
                     passwd,
                     passwdlen,
                     maxmem, 
                     maxmemfrac,
                     maxtime )
        != 0)
        return basic_error(env, "hash_worker_failed");

    /* RETURN binary */
    ERL_NIF_TERM ret;
    memcpy(enif_make_new_binary(env, HASH_SIZE, &ret), &hash[0], HASH_SIZE);

    free(options);
    return ret;
}

static ERL_NIF_TERM
verify(ErlNifEnv * env, int argc, const ERL_NIF_TERM argv[])
{
    /* Get Options */
    scrypt_params * options = parse_options( env, argv ); 
    uint8_t * passwd = options->passwd;
    size_t passwdlen = options->passwdlen;
    size_t maxmem = options->maxmem;
    double maxmemfrac = options->maxmemfrac;
    double maxtime = options->maxtime;

    /* Get Hash */
	ErlNifBinary hash;
	if (!enif_inspect_binary(env, argv[4], &hash))
		return enif_make_badarg(env);
    if (hash.size != HASH_SIZE)
        return enif_make_atom(env, "false");
    uint8_t * header = hash.data;
        
    /* Do Verify */
    uint8_t dk[ 64 ];
    char * ret = NULL;
    int rc;
    if ((rc = verify_worker( header,
                             dk,
                             passwd,
                             passwdlen,
                             maxmem,
                             maxmemfrac,
                             maxtime ))
        != 0) {
        printf("bad return: %d\n", rc);
        ret = "false";
    }
    else 
        ret = "true";

    free(options);
    return enif_make_atom(env, ret);
}

static ERL_NIF_TERM
scrypt_encrypt(ErlNifEnv * env, int argc, const ERL_NIF_TERM argv[])
{
    /* Get Options */
    scrypt_params * options = parse_options( env, argv ); 
    uint8_t * passwd = options->passwd;
    size_t passwdlen = options->passwdlen;
    size_t maxmem = options->maxmem;
    double maxmemfrac = options->maxmemfrac;
    double maxtime = options->maxtime;

    uint8_t * plaintext;
    size_t plaintext_len;

    /* Get plaintext */
    ErlNifBinary plaintext_bin;
    if (!enif_inspect_iolist_as_binary(env, argv[4], &plaintext_bin))
		return enif_make_badarg(env);
    plaintext = plaintext_bin.data;
    plaintext_len = plaintext_bin.size;        

    /* Generate Keys */
    size_t outlen = HASH_SIZE + plaintext_len + 32;
    uint8_t outbuf[ outlen ];
    uint8_t dk[64];
	uint8_t hbuf[32];
	uint8_t header[96];
	uint8_t * key_enc = dk;
	uint8_t * key_hmac = &dk[32];
	int rc;
	HMAC_SHA256_CTX hctx;
	AES_KEY key_enc_exp;
	struct crypto_aesctr * AES;

	if ((rc = hash_worker(header, dk, passwd, passwdlen,
                          maxmem, maxmemfrac, maxtime)) != 0)
		return basic_error(env, "hash_worker_failed");

	/* Copy header into output buffer. */
	memcpy(outbuf, header, 96);

	/* Encrypt data. */
	if (AES_set_encrypt_key(key_enc, 256, &key_enc_exp))
		return (5);
	if ((AES = crypto_aesctr_init(&key_enc_exp, 0)) == NULL)
		return (6);
	crypto_aesctr_stream(AES, plaintext, &outbuf[96], plaintext_len);
	crypto_aesctr_free(AES);

	/* Add signature. */
	HMAC_SHA256_Init(&hctx, key_hmac, 32);
	HMAC_SHA256_Update(&hctx, outbuf, 96 + plaintext_len);
	HMAC_SHA256_Final(hbuf, &hctx);
	memcpy(&outbuf[96 + plaintext_len], hbuf, 32);

	/* Zero sensitive data. */
	memset(dk, 0, 64);
	memset(&key_enc_exp, 0, sizeof(AES_KEY));

    /* Do Encryption */
    ERL_NIF_TERM ret;
    memcpy(enif_make_new_binary(env, outlen, &ret), &outbuf, outlen);
    
    free(options);
    return ret;
}

static ERL_NIF_TERM
scrypt_decrypt(ErlNifEnv * env, int argc, const ERL_NIF_TERM argv[]) 
{    
    /* Get Options */
    scrypt_params * options = parse_options( env, argv ); 
    uint8_t * passwd = options->passwd;
    size_t passwdlen = options->passwdlen;
    size_t maxmem = options->maxmem;
    double maxmemfrac = options->maxmemfrac;
    double maxtime = options->maxtime;

    uint8_t hbuf[32];
	uint8_t dk[64];
	uint8_t * key_enc = dk;
	uint8_t * key_hmac = &dk[32];
	HMAC_SHA256_CTX hctx;
	AES_KEY key_enc_exp;
	struct crypto_aesctr * AES;

    uint8_t * inbuf;
    size_t inbuflen;    
    
    /* Get ciphertext */
    ErlNifBinary ciphertext_bin;
    if (!enif_inspect_iolist_as_binary(env, argv[4], &ciphertext_bin))
		return enif_make_badarg(env);
    inbuf = ciphertext_bin.data;
    inbuflen = ciphertext_bin.size;     

	/*
	 * All versions of the scrypt format will start with "scrypt" and
	 * have at least 7 bytes of header.
	 */
	if ((inbuflen < 7) || (memcmp(inbuf, "scrypt", 6) != 0))
		return (7);

	/* Check the format. */
	if (inbuf[6] != 0)
		return (8);

	/* We must have at least 128 bytes. */
	if (inbuflen < 128)
		return (7);

	/* Parse the header and generate derived keys. */
	if (verify_worker( inbuf, 
                       dk, 
                       passwd,
                       passwdlen,
                       maxmem,
                       maxmemfrac,
                       maxtime) 
        != 0)
		return basic_error(env, "verify_worker_failed");

	/* Decrypt data. */
    size_t outlen = inbuflen - 128;
    uint8_t outbuf[ outlen ]; 
	if (AES_set_encrypt_key(key_enc, 256, &key_enc_exp))
		return (5);
	if ((AES = crypto_aesctr_init(&key_enc_exp, 0)) == NULL)
		return (6);
	crypto_aesctr_stream(AES, &inbuf[96], outbuf, outlen);
	crypto_aesctr_free(AES);	

	/* Verify signature. */
	HMAC_SHA256_Init(&hctx, key_hmac, 32);
	HMAC_SHA256_Update(&hctx, inbuf, inbuflen - 32);
	HMAC_SHA256_Final(hbuf, &hctx);
	if (memcmp(hbuf, &inbuf[inbuflen - 32], 32))
		return (7);

	/* Zero sensitive data. */
	memset(dk, 0, 64);
	memset(&key_enc_exp, 0, sizeof(AES_KEY));

    /* Return */
    ERL_NIF_TERM ret;
    memcpy(enif_make_new_binary(env, outlen, &ret), &outbuf, outlen);

    free(options);
    return ret;
}

static ErlNifFunc nif_funcs[] = {
	{"hash", 4, hash},
	{"verify", 5, verify},
    {"encrypt", 5, scrypt_encrypt},
    {"decrypt", 5, scrypt_decrypt}
}; 

ERL_NIF_INIT(scrypt_nif, nif_funcs, NULL, NULL, NULL, NULL)
