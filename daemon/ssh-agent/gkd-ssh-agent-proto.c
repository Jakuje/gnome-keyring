/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-ssh-agent-proto.c - SSH agent protocol helpers

   Copyright (C) 2007 Stefan Walter

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkd-ssh-agent-private.h"

#include "gkm/gkm-data-der.h"

#include "egg/egg-buffer.h"

#include <gck/gck.h>

#include <glib.h>

#include <string.h>

/* -----------------------------------------------------------------------------
 * QUARKS
 */

GQuark OID_ANSI_SECP256R1;
GQuark OID_ANSI_SECP384R1;
GQuark OID_ANSI_SECP521R1;

void
gkd_ssh_agent_proto_init_quarks (void)
{
	static volatile gsize quarks_inited = 0;

	if (g_once_init_enter (&quarks_inited)) {

		#define QUARK(name, value) \
			name = g_quark_from_static_string(value)

		QUARK (OID_ANSI_SECP256R1, "1.2.840.10045.3.1.7");
		QUARK (OID_ANSI_SECP384R1, "1.3.132.0.34");
		QUARK (OID_ANSI_SECP521R1, "1.3.132.0.35");

		#undef QUARK

		g_once_init_leave (&quarks_inited, 1);
	}
}

gulong
gkd_ssh_agent_proto_keytype_to_algo (const gchar *salgo)
{
	g_return_val_if_fail (salgo, G_MAXULONG);
	if (strcmp (salgo, "ssh-rsa") == 0)
		return CKK_RSA;
	else if (strcmp (salgo, "ssh-dss") == 0)
		return CKK_DSA;
	else if ((strcmp (salgo, "ecdsa-sha2-nistp256") == 0)
	    || (strcmp (salgo, "ecdsa-sha2-nistp384") == 0)
	    || (strcmp (salgo, "ecdsa-sha2-nistp521") == 0))
		return CKK_EC;
	return G_MAXULONG;
}

GQuark
gkd_ssh_agent_proto_curve_to_oid (const gchar *salgo)
{
	g_return_val_if_fail (salgo, 0);
	if (strcmp (salgo, "nistp256") == 0)
		return OID_ANSI_SECP256R1;
	if (strcmp (salgo, "nistp384") == 0)
		return OID_ANSI_SECP384R1;
	if (strcmp (salgo, "nistp521") == 0)
		return OID_ANSI_SECP521R1;
	return 0;
}

const gchar*
gkd_ssh_agent_proto_oid_to_curve (GQuark oid)
{
	g_return_val_if_fail (oid, 0);
	if (oid == OID_ANSI_SECP256R1)
		return "nistp256";
	else if (oid == OID_ANSI_SECP384R1)
		return "nistp384";
	else if (oid == OID_ANSI_SECP521R1)
		return "nistp521";
	return NULL;
}

const gchar*
gkd_ssh_agent_proto_oid_to_keytype (GQuark oid)
{
	g_return_val_if_fail (oid, 0);
	if (oid == OID_ANSI_SECP256R1)
		return "ecdsa-sha2-nistp256";
	else if (oid == OID_ANSI_SECP384R1)
		return "ecdsa-sha2-nistp384";
	else if (oid == OID_ANSI_SECP521R1)
		return "ecdsa-sha2-nistp521";
	return NULL;
}

const gchar*
gkd_ssh_agent_proto_algo_to_keytype (gulong algo, GQuark oid)
{
	if (algo == CKK_RSA && oid == 0)
		return "ssh-rsa";
	else if (algo == CKK_DSA && oid == 0)
		return "ssh-dss";
	else if (algo == CKK_EC)
		return gkd_ssh_agent_proto_oid_to_keytype (oid);
	return NULL;
}


GQuark
gkd_ssh_agent_proto_oid_from_params (GckAttributes *attrs)
{
	GBytes *bytes;
	const GckAttribute *attr;
	GQuark oid;

	g_assert (attrs);

	attr = gck_attributes_find (attrs, CKA_EC_PARAMS);
	if (attr == NULL)
		g_return_val_if_reached (0);

	bytes = g_bytes_new (attr->value, attr->length);

	oid = gkm_data_der_oid_from_params (bytes);

	g_bytes_unref (bytes);

	return oid;
}

gboolean
gkd_ssh_agent_proto_read_mpi (EggBuffer *req, gsize *offset,
                              GckBuilder *builder,
                              CK_ATTRIBUTE_TYPE type)
{
	const guchar *data;
	gsize len;

	if (!egg_buffer_get_byte_array (req, *offset, offset, &data, &len))
		return FALSE;

	/* Convert to unsigned format */
	if (len >= 2 && data[0] == 0 && (data[1] & 0x80)) {
		++data;
		--len;
	}

	gck_builder_add_data (builder, type, data, len);
	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_mpi_v1 (EggBuffer *req,
                                 gsize *offset,
                                 GckBuilder *attrs,
                                 CK_ATTRIBUTE_TYPE type)
{
	const guchar *data;
	gsize bytes;
	guint16 bits;

	/* Get the number of bits */
	if (!egg_buffer_get_uint16 (req, *offset, offset, &bits))
		return FALSE;

	/* Figure out the number of binary bytes following */
	bytes = (bits + 7) / 8;
	if (bytes > 8 * 1024)
		return FALSE;

	/* Pull these out directly */
	if (req->len < *offset + bytes)
		return FALSE;
	data = req->buf + *offset;
	*offset += bytes;

	gck_builder_add_data (attrs, type, data, bytes);
	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_string (EggBuffer *req,
                                 gsize *offset,
                                 GckBuilder *attrs,
                                 CK_ATTRIBUTE_TYPE type)
{
       const guchar *data;
       gsize len;

       if (!egg_buffer_get_byte_array (req, *offset, offset, &data, &len))
               return FALSE;

       gck_builder_add_data (attrs, type, data, len);
       return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_mpi (EggBuffer *resp,
                               const GckAttribute *attr)
{
	const guchar *value;
	guchar *data;
	gsize n_extra;

	g_assert (resp);
	g_assert (attr);

	/* Convert from unsigned format */
	n_extra = 0;
	value = attr->value;
	if (attr->length && (value[0] & 0x80))
		++n_extra;

	data = egg_buffer_add_byte_array_empty (resp, attr->length + n_extra);
	if (data == NULL)
		return FALSE;

	memset (data, 0, n_extra);
	memcpy (data + n_extra, attr->value, attr->length);
	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_mpi_v1 (EggBuffer *resp,
                                  const GckAttribute *attr)
{
	guchar *data;

	g_return_val_if_fail (attr->length * 8 < G_MAXUSHORT, FALSE);

	if (!egg_buffer_add_uint16 (resp, attr->length * 8))
		return FALSE;

	data = egg_buffer_add_empty (resp, attr->length);
	if (data == NULL)
		return FALSE;
	memcpy (data, attr->value, attr->length);
	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_string (EggBuffer *resp,
                                  const GckAttribute *attr)
{
       guchar *data;

       g_assert (resp);
       g_assert (attr);

       data = egg_buffer_add_byte_array_empty (resp, attr->length);
       if (data == NULL)
               return FALSE;

       memcpy (data, attr->value, attr->length);
       return TRUE;
}

const guchar*
gkd_ssh_agent_proto_read_challenge_v1 (EggBuffer *req, gsize *offset, gsize *n_challenge)
{
	const guchar *data;
	gsize bytes;
	guint16 bits;

	/* Get the number of bits */
	if (!egg_buffer_get_uint16 (req, *offset, offset, &bits))
		return FALSE;

	/* Figure out the number of binary bytes following */
	bytes = (bits + 7) / 8;
	if (bytes > 8 * 1024)
		return FALSE;

	/* Pull these out directly */
	if (req->len < *offset + bytes)
		return FALSE;
	data = req->buf + *offset;
	*offset += bytes;
	*n_challenge = bytes;
	return data;
}

gboolean
gkd_ssh_agent_proto_read_public (EggBuffer *req,
                                 gsize *offset,
                                 GckBuilder *attrs,
                                 gulong *algo)
{
	gboolean ret;
	gchar *stype;
	gulong alg;

	g_assert (req);
	g_assert (offset);

	/* The string algorithm */
	if (!egg_buffer_get_string (req, *offset, offset, &stype, (EggBufferAllocator)g_realloc))
		return FALSE;

	alg = gkd_ssh_agent_proto_keytype_to_algo (stype);
	if (alg == G_MAXULONG) {
		g_warning ("unsupported algorithm from SSH: %s", stype);
		g_free (stype);
		return FALSE;
	}

	g_free (stype);
	switch (alg) {
	case CKK_RSA:
		ret = gkd_ssh_agent_proto_read_public_rsa (req, offset, attrs);
		break;
	case CKK_DSA:
		ret = gkd_ssh_agent_proto_read_public_dsa (req, offset, attrs);
		break;
	case CKK_EC:
		ret = gkd_ssh_agent_proto_read_public_ecdsa (req, offset, attrs);
		break;
	default:
		g_assert_not_reached ();
		return FALSE;
	}

	if (!ret) {
		g_warning ("couldn't read incoming SSH public key");
		return FALSE;
	}

	if (algo)
		*algo = alg;
	return ret;
}

gboolean
gkd_ssh_agent_proto_read_pair_rsa (EggBuffer *req,
                                   gsize *offset,
                                   GckBuilder *priv_attrs,
                                   GckBuilder *pub_attrs)
{
	const GckAttribute *attr;

	g_assert (req);
	g_assert (offset);
	g_assert (priv_attrs);
	g_assert (pub_attrs);

	if (!gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_MODULUS) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_PUBLIC_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_PRIVATE_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_COEFFICIENT) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_PRIME_1) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_PRIME_2))
		return FALSE;

	/* Copy attributes to the public key */
	attr = gck_builder_find (priv_attrs, CKA_MODULUS);
	gck_builder_add_attribute (pub_attrs, attr);
	attr = gck_builder_find (priv_attrs, CKA_PUBLIC_EXPONENT);
	gck_builder_add_attribute (pub_attrs, attr);

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (priv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
	gck_builder_add_ulong (priv_attrs, CKA_KEY_TYPE, CKK_RSA);
	gck_builder_add_ulong (pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (pub_attrs, CKA_KEY_TYPE, CKK_RSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_pair_v1 (EggBuffer *req,
                                  gsize *offset,
                                  GckBuilder *priv_attrs,
                                  GckBuilder *pub_attrs)
{
	const GckAttribute *attr;

	g_assert (req);
	g_assert (offset);
	g_assert (priv_attrs);
	g_assert (pub_attrs);

	if (!gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_MODULUS) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_PUBLIC_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_PRIVATE_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_COEFFICIENT) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_PRIME_1) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_PRIME_2))
		return FALSE;

	/* Copy attributes to the public key */
	attr = gck_builder_find (priv_attrs, CKA_MODULUS);
	gck_builder_add_attribute (pub_attrs, attr);
	attr = gck_builder_find (priv_attrs, CKA_PUBLIC_EXPONENT);
	gck_builder_add_attribute (pub_attrs, attr);

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (priv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
	gck_builder_add_ulong (priv_attrs, CKA_KEY_TYPE, CKK_RSA);
	gck_builder_add_ulong (pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (pub_attrs, CKA_KEY_TYPE, CKK_RSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_public_rsa (EggBuffer *req,
                                     gsize *offset,
                                     GckBuilder *attrs)
{
	g_assert (req);
	g_assert (offset);
	g_assert (attrs);

	if (!gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_PUBLIC_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_MODULUS))
		return FALSE;

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (attrs, CKA_KEY_TYPE, CKK_RSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_public_v1 (EggBuffer *req,
                                    gsize *offset,
                                    GckBuilder *attrs)
{
	guint32 bits;

	g_assert (req);
	g_assert (offset);
	g_assert (attrs);

	if (!egg_buffer_get_uint32 (req, *offset, offset, &bits))
		return FALSE;

	if (!gkd_ssh_agent_proto_read_mpi_v1 (req, offset, attrs, CKA_PUBLIC_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, attrs, CKA_MODULUS))
		return FALSE;

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (attrs, CKA_KEY_TYPE, CKK_RSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_pair_dsa (EggBuffer *req,
                                   gsize *offset,
                                   GckBuilder *priv_attrs,
                                   GckBuilder *pub_attrs)
{
	const GckAttribute *attr;

	g_assert (req);
	g_assert (offset);
	g_assert (priv_attrs);
	g_assert (pub_attrs);

	if (!gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_PRIME) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_SUBPRIME) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_BASE) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, pub_attrs, CKA_VALUE) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_VALUE))
		return FALSE;

	/* Copy attributes to the public key */
	attr = gck_builder_find (priv_attrs, CKA_PRIME);
	gck_builder_add_attribute (pub_attrs, attr);
	attr = gck_builder_find (priv_attrs, CKA_SUBPRIME);
	gck_builder_add_attribute (pub_attrs, attr);
	attr = gck_builder_find (priv_attrs, CKA_BASE);
	gck_builder_add_attribute (pub_attrs, attr);

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (priv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
	gck_builder_add_ulong (priv_attrs, CKA_KEY_TYPE, CKK_DSA);
	gck_builder_add_ulong (pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (pub_attrs, CKA_KEY_TYPE, CKK_DSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_public_dsa (EggBuffer *req,
                                     gsize *offset,
                                     GckBuilder *attrs)
{
	g_assert (req);
	g_assert (offset);
	g_assert (attrs);

	if (!gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_PRIME) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_SUBPRIME) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_BASE) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_VALUE))
		return FALSE;

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (attrs, CKA_KEY_TYPE, CKK_DSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_ecdsa_curve (EggBuffer *req,
                                     gsize *offset,
                                     GckBuilder *attrs)
{
	GBytes *params;
	gchar *curve_name;
	const guchar *params_data;
	GQuark oid;
	gsize params_len;

	g_assert (req);
	g_assert (offset);
	g_assert (attrs);

	gkd_ssh_agent_proto_init_quarks ();

	/* first part is the curve name (nistp* part of key name) and needs
	 * to be converted to CKA_EC_PARAMS
	 */
	if (!egg_buffer_get_string (req, *offset, offset, &curve_name,
                                (EggBufferAllocator)g_realloc))
		return FALSE;

	oid = gkd_ssh_agent_proto_curve_to_oid (curve_name);
	g_return_val_if_fail (oid, FALSE);

	params = gkm_data_der_get_ec_params (oid);
	g_return_val_if_fail (params != NULL, FALSE);

	params_data = g_bytes_get_data (params, &params_len);
	gck_builder_add_data (attrs, CKA_EC_PARAMS, params_data, params_len);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_pair_ecdsa (EggBuffer *req,
                                     gsize *offset,
                                     GckBuilder *priv_attrs,
                                     GckBuilder *pub_attrs)
{
	const GckAttribute *attr;

	g_assert (req);
	g_assert (offset);
	g_assert (priv_attrs);
	g_assert (pub_attrs);

	if (!gkd_ssh_agent_proto_read_ecdsa_curve (req, offset, priv_attrs) ||
	    !gkd_ssh_agent_proto_read_string (req, offset, priv_attrs, CKA_EC_POINT) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_VALUE))
		return FALSE;

	/* Copy attributes to the public key */
	attr = gck_builder_find (priv_attrs, CKA_EC_POINT);
	gck_builder_add_attribute (pub_attrs, attr);
	attr = gck_builder_find (priv_attrs, CKA_EC_PARAMS);
	gck_builder_add_attribute (pub_attrs, attr);

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (priv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
	gck_builder_add_ulong (priv_attrs, CKA_KEY_TYPE, CKK_EC);
	gck_builder_add_ulong (pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (pub_attrs, CKA_KEY_TYPE, CKK_EC);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_public_ecdsa (EggBuffer *req,
                                       gsize *offset,
                                       GckBuilder *attrs)
{
	g_assert (req);
	g_assert (offset);
	g_assert (attrs);

	if (!gkd_ssh_agent_proto_read_ecdsa_curve (req, offset, attrs) ||
	    !gkd_ssh_agent_proto_read_string (req, offset, attrs, CKA_EC_POINT))
		return FALSE;

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (attrs, CKA_KEY_TYPE, CKK_EC);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_public (EggBuffer *resp, GckAttributes *attrs)
{
	gboolean ret = FALSE;
	const gchar *salgo;
	GQuark oid = 0;
	gulong algo;

	g_assert (resp);
	g_assert (attrs);

	gkd_ssh_agent_proto_init_quarks ();

	if (!gck_attributes_find_ulong (attrs, CKA_KEY_TYPE, &algo))
		g_return_val_if_reached (FALSE);
	if (algo == CKK_EC) {
		oid = gkd_ssh_agent_proto_oid_from_params (attrs);
		if (!oid)
			return FALSE;
	}

	salgo = gkd_ssh_agent_proto_algo_to_keytype (algo, oid);
	g_assert (salgo);
	egg_buffer_add_string (resp, salgo);

	switch (algo) {
	case CKK_RSA:
		ret = gkd_ssh_agent_proto_write_public_rsa (resp, attrs);
		break;

	case CKK_DSA:
		ret = gkd_ssh_agent_proto_write_public_dsa (resp, attrs);
		break;

	case CKK_EC:
		ret = gkd_ssh_agent_proto_write_public_ecdsa (resp, attrs);
		break;

	default:
		g_return_val_if_reached (FALSE);
		break;
	}

	return ret;
}

gboolean
gkd_ssh_agent_proto_write_public_rsa (EggBuffer *resp, GckAttributes *attrs)
{
	const GckAttribute *attr;

	g_assert (resp);
	g_assert (attrs);

	attr = gck_attributes_find (attrs, CKA_PUBLIC_EXPONENT);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	attr = gck_attributes_find (attrs, CKA_MODULUS);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_public_dsa (EggBuffer *resp, GckAttributes *attrs)
{
	const GckAttribute *attr;

	g_assert (resp);
	g_assert (attrs);

	attr = gck_attributes_find (attrs, CKA_PRIME);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	attr = gck_attributes_find (attrs, CKA_SUBPRIME);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	attr = gck_attributes_find (attrs, CKA_BASE);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	attr = gck_attributes_find (attrs, CKA_VALUE);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_public_ecdsa (EggBuffer *resp, GckAttributes *attrs)
{
	const GckAttribute *attr;
	GQuark oid;
	const gchar *key_type;
	guchar *data;

	g_assert (resp);
	g_assert (attrs);

	gkd_ssh_agent_proto_init_quarks ();

	oid = gkd_ssh_agent_proto_oid_from_params (attrs);
	g_return_val_if_fail (oid, FALSE);

	key_type = gkd_ssh_agent_proto_oid_to_curve (oid);
	g_return_val_if_fail (key_type != NULL, FALSE);

	data = egg_buffer_add_byte_array_empty (resp, strlen(key_type));
	if (data == NULL)
		return FALSE;

	memcpy (data, key_type, strlen(key_type));

	attr = gck_attributes_find (attrs, CKA_EC_POINT);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_string (resp, attr))
		return FALSE;

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_public_v1 (EggBuffer *resp, GckAttributes *attrs)
{
	const GckAttribute *attr;
	gulong bits;

	g_assert (resp);
	g_assert (attrs);

	/* This is always an RSA key. */

	/* Write out the number of bits of the key */
	if (!gck_attributes_find_ulong (attrs, CKA_MODULUS_BITS, &bits))
		g_return_val_if_reached (FALSE);
	egg_buffer_add_uint32 (resp, bits);

	/* Write out the exponent */
	attr = gck_attributes_find (attrs, CKA_PUBLIC_EXPONENT);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi_v1 (resp, attr))
		return FALSE;

	/* Write out the modulus */
	attr = gck_attributes_find (attrs, CKA_MODULUS);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi_v1 (resp, attr))
		return FALSE;

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_signature_rsa (EggBuffer *resp, CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	return egg_buffer_add_byte_array (resp, signature, n_signature);
}

gboolean
gkd_ssh_agent_proto_write_signature_dsa (EggBuffer *resp, CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	g_return_val_if_fail (n_signature == 40, FALSE);
	return egg_buffer_add_byte_array (resp, signature, n_signature);
}

gboolean
gkd_ssh_agent_proto_write_signature_ecdsa (EggBuffer *resp, CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	return egg_buffer_add_byte_array (resp, signature, n_signature);
}
