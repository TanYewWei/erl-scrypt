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
#include "lib/params.h"
#include "lib/sha256.h"
#include "lib/memlimit.h"
#include "lib/sysendian.h"
#include "lib/warn.h"

#define HASH_SIZE 96

/* ----------------------------------------------------------------------
 * ERLANG NIF FUNCTIONS
 * ---------------------------------------------------------------------- */

ERL_NIF_TERM
make_basic_error(ErlNifEnv* env, char * reason) 
{
    return enif_make_tuple2(env, 
                            enif_make_atom(env, "error"), 
                            enif_make_atom(env, reason));
}

/*
 * Implementation copied largely from lib/scryptenc/scryptenc.c
 */
static ERL_NIF_TERM
hash(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{    
    uint8_t * passwd;
    size_t passwdlen;
    size_t maxmem; 
    double maxmemfrac;
    double maxtime;

    uint8_t header[96];
    uint8_t dk[64];
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

    /* Get password and password length */
    ErlNifBinary pass_bin;    
    if (!enif_inspect_iolist_as_binary(env, argv[0], &pass_bin))
		return enif_make_badarg(env);
    passwd = (uint8_t *)pass_bin.data;
    passwdlen = (size_t)pass_bin.size;

    /* Get options */
    int maxmem_int;
    if (!enif_get_int(env, argv[1], &maxmem_int))
		return enif_make_badarg(env);
    maxmem = (size_t)maxmem_int;

    if (!enif_get_double(env, argv[2], &maxmemfrac))
		return enif_make_badarg(env);

    int maxtime_int;
    if (!enif_get_int(env, argv[3], &maxtime_int))
		return enif_make_badarg(env);  
    maxtime = (double)maxtime_int;    

    /* Calculate parameters from options */
    if ((rc = pickparams(maxmem, maxmemfrac, maxtime, &logN, &r, &p) != 0))
        return (rc);
    N = (uint64_t)(1) << logN;

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

    /* RETURN binary */
    ERL_NIF_TERM ret;
    memcpy(enif_make_new_binary(env, HASH_SIZE, &ret), &header[0], HASH_SIZE);
    return ret;
}

static ERL_NIF_TERM
verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    /* Get Password and Hash */
    ErlNifBinary pass;
	ErlNifBinary hash;
    if (!enif_inspect_iolist_as_binary(env, argv[0], &pass))
		return enif_make_badarg(env);
	if (!enif_inspect_binary(env, argv[1], &hash))
		return enif_make_badarg(env);

    /* Validate Hash Len */
    printf("hash size: %zd", hash.size);
    if (hash.size != HASH_SIZE)
        return enif_make_atom(env, "false");

    uint8_t * passwd = pass.data;
    size_t passwdlen = pass.size;
    uint8_t * header = hash.data;

    /* Get options */
    size_t maxmem; 
    double maxmemfrac;
    double maxtime;

    int maxmem_int;
    if (!enif_get_int(env, argv[2], &maxmem_int))
		return enif_make_badarg(env);
    maxmem = (size_t)maxmem_int;

    if (!enif_get_double(env, argv[3], &maxmemfrac))
		return enif_make_badarg(env);

    int maxtime_int;
    if (!enif_get_int(env, argv[4], &maxtime_int))
		return enif_make_badarg(env);  
    maxtime = (double)maxtime_int;  
    
    /* Rest taken from scryptenc.c */
    uint8_t salt[32];
	uint8_t hbuf[32];
	int logN;
	uint32_t r;
	uint32_t p;
	uint64_t N;
	SHA256_CTX ctx;
    uint8_t dk[64];
	uint8_t * key_hmac = &dk[32];
	HMAC_SHA256_CTX hctx;
	int rc;

	/* Parse N, r, p, salt. */
	logN = header[7];
	r = be32dec(&header[8]);
	p = be32dec(&header[12]);
	memcpy(salt, &header[16], 32);
    printf("here 0");
	/* Verify header checksum. */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, header, 48);
	SHA256_Final(hbuf, &ctx);
	if (memcmp(&header[48], hbuf, 16))
		return enif_make_atom(env, "false");

    printf("here 1");

	/*
	 * Check whether the provided parameters are valid and whether the
	 * key derivation function can be computed within the allowed memory
	 * and CPU time.
	 */
	if ((rc = checkparams(maxmem, maxmemfrac, maxtime, logN, r, p)) != 0)
		return enif_make_atom(env, "false");
    printf("here 2");

	/* Compute the derived keys. */
	N = (uint64_t)(1) << logN;
	if (crypto_scrypt(passwd, passwdlen, salt, 32, N, r, p, dk, 64))
		return enif_make_atom(env, "false");
    printf("here 3");

	/* Check header signature (i.e., verify password). */
	HMAC_SHA256_Init(&hctx, key_hmac, 32);
	HMAC_SHA256_Update(&hctx, header, 64);
	HMAC_SHA256_Final(hbuf, &hctx);

	if (memcmp(hbuf, &header[64], 32)) // Bad Password
		return enif_make_atom(env, "false");
    else 
        return enif_make_atom(env, "true");
}

static ErlNifFunc nif_funcs[] = {
	{"hash", 4, hash},
	{"verify", 5, verify}
}; 

ERL_NIF_INIT(scrypt_nif, nif_funcs, NULL, NULL, NULL, NULL)
