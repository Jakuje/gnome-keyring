/*
 * gnome-keyring
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkm-crypto.h"
#include "gkm-ecdsa-mechanism.h"
#include "gkm-session.h"
#include "gkm-sexp.h"
#include "gkm-sexp-key.h"

#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

/*
 * Private
 */

static const gchar *
gkm_ecdsa_get_hash_algorithm (gcry_sexp_t sexp)
{
	CK_ULONG key_bits;

	/* from rfc5656 */
	key_bits = gcry_pk_get_nbits(sexp);
	if (key_bits <= 256)
		return "sha256";
	else if (key_bits <= 384)
		return "sha384";
	else
		return "sha512";
}

/* ----------------------------------------------------------------------------
 * PUBLIC
 */

CK_RV
gkm_ecdsa_mechanism_sign (gcry_sexp_t sexp, CK_BYTE_PTR data, CK_ULONG n_data,
                          CK_BYTE_PTR signature, CK_ULONG_PTR n_signature)
{
	gcry_sexp_t ssig, splain;
	gcry_error_t gcry;
	CK_ULONG size, key_bytes;
	CK_RV rv;
	const gchar *hash_alg;

	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	/*if (n_data != 20)
		return CKR_DATA_LEN_RANGE;*/

	/* If no output, then don't process */
	key_bytes = gcry_pk_get_nbits(sexp)/8;
	if (!signature) {
		*n_signature = key_bytes * 2;
		return CKR_OK;
	} else if (*n_signature < key_bytes * 2) {
		*n_signature = key_bytes * 2;
		return CKR_BUFFER_TOO_SMALL;
	}

	hash_alg = gkm_ecdsa_get_hash_algorithm (sexp);

	/* Prepare the input s-expression */
	gcry = gcry_sexp_build (&splain, NULL, "(data (flags raw) (hash-algo %s) (value %b))",
                                hash_alg, n_data, data);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	/* Do the magic */
	gcry = gcry_pk_sign (&ssig, splain, sexp);
	gcry_sexp_release (splain);

	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_message ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_FUNCTION_FAILED;
	}

	size = key_bytes;
	rv = gkm_crypto_sexp_to_buffer (ssig, signature, &size, NULL, "ecdsa", "r", NULL);
	if (rv == CKR_OK) {
		g_return_val_if_fail (size == key_bytes, CKR_GENERAL_ERROR);
		rv = gkm_crypto_sexp_to_buffer (ssig, signature + key_bytes, &size, NULL, "ecdsa", "s", NULL);
		if (rv == CKR_OK) {
			g_return_val_if_fail (size == key_bytes, CKR_GENERAL_ERROR);
			*n_signature = key_bytes*2;
		}
	}

	gcry_sexp_release (ssig);
	return CKR_OK;
}

CK_RV
gkm_ecdsa_mechanism_verify (gcry_sexp_t sexp, CK_BYTE_PTR data, CK_ULONG n_data,
                            CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	gcry_sexp_t ssig, splain;
	gcry_error_t gcry;
	CK_ULONG key_bytes;
	const gchar *hash_alg;

	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	key_bytes = gcry_pk_get_nbits(sexp)/8;
	/*if (n_data != 20)
		return CKR_DATA_LEN_RANGE;*/
	if (n_signature != key_bytes*2)
		return CKR_SIGNATURE_LEN_RANGE;

	hash_alg = gkm_ecdsa_get_hash_algorithm (sexp);

	/* Prepare the input s-expressions */
	gcry = gcry_sexp_build (&splain, NULL, "(data (flags raw) (hash-algo %s) (value %b))",
                                hash_alg, n_data, data);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	gcry = gcry_sexp_build (&ssig, NULL, "(sig-val (ecdsa (r %b) (s %b)))",
                                key_bytes, signature, key_bytes, signature + key_bytes);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	/* Do the magic */
	gcry = gcry_pk_verify (ssig, splain, sexp);
	gcry_sexp_release (splain);
	gcry_sexp_release (ssig);

	/* TODO: See if any other codes should be mapped */
	if (gcry_err_code (gcry) == GPG_ERR_BAD_SIGNATURE) {
		return CKR_SIGNATURE_INVALID;
	} else if (gcry) {
		g_message ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

