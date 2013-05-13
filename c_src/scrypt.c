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
#include "lib/sha256.h"
#include "lib/memlimit.h"
#include "lib/readpass.h"
#include "lib/sysendian.h"
#include "lib/warn.h"


/* ----------------------------------------------------------------------
 * ERLANG NIF FUNCTIONS
 * ---------------------------------------------------------------------- */

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
    unsigned int pass_len;
    if (!enif_inspect_iolist_as_binary(env, argv[0], &pass_bin))
		return enif_make_badarg(env);
    if (!enif_get_uint(env, argv[1], &pass_len))
		return enif_make_badarg(env);

    passwd = (uint8_t *)pass_bin.data;
    passwdlen = (size_t)pass_len;

    /* Get options */
    int maxmem_int;
    if (!enif_get_uint(env, argv[2], &maxmem_int))
		return enif_make_badarg(env);
    if (!enif_get_double(env, argv[3], &maxmemfrac))
		return enif_make_badarg(env);
    if (!enif_get_double(env, argv[4], &maxtime))
		return enif_make_badarg(env);

    maxmem = (size_t)maxmem_int;

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
    scrypt_SHA256_Update(&ctx, header, 48);
    scrypt_SHA256_Final(hbuf, &ctx);
    memcpy(&header[48], hbuf, 16);

    /* Add header signature (used for verifying password). */
    HMAC_SHA256_Init(&hctx, key_hmac, 32);
    HMAC_SHA256_Update(&hctx, header, 64);
    HMAC_SHA256_Final(hbuf, &hctx);
    memcpy(&header[64], hbuf, 32);

    /* RETURN binary */
    ERL_NIF_TERM hash;
    memcpy(enif_make_new_binary(env, 96, &hash), header, 96);
    return hash;
}

//static ERL_NIF_TERM
//verify_hash(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
//{
//}

static ErlNifFunc nif_funcs[] = {
	{"hash", 5, hash}
	//{"verify_hash", 2, verify_hash}
}; 

ERL_NIF_INIT(scrypt, nif_funcs, NULL, NULL, NULL, NULL)
