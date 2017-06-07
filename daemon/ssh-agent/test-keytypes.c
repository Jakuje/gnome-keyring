/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-keytypes.c: Parsing and generating key types from SSH

   Copyright (C) 2017 Red Hat, Inc.

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   <http://www.gnu.org/licenses/>.

   Author: Jakub Jelen <jjelen@redhat.com>
*/

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>

#include "pkcs11/pkcs11.h"
//#include "gkd-ssh-agent.h"
#include "gkd-ssh-agent-private.h"

struct alg {
	gchar		*name;
	CK_KEY_TYPE	 id;
	gchar		*ec_curve;
};

/* known algorithms */
static const struct alg algs_known[] = {
	{ "ssh-rsa", CKK_RSA, NULL },
	{ "ssh-dss", CKK_DSA, NULL },
	{ "ecdsa-sha2-nistp256", CKK_EC, "NIST P-256" },
	{ "ecdsa-sha2-nistp384", CKK_EC, "NIST P-384" },
	{ "ecdsa-sha2-nistp521", CKK_EC, "NIST P-521" },

	/* terminator */
	{ NULL, 0, NULL }
};

/* unknown algorithms */
static const struct alg algs_parse_unknown[] = {
	/* no certificates */
	{ "ssh-rsa-cert-v01@openssh.com", G_MAXULONG, NULL },
	{ "ssh-dss-cert-v01@openssh.com", G_MAXULONG, NULL },
	{ "ecdsa-sha2-nistp256-cert-v01@openssh.com", G_MAXULONG, NULL },
	{ "ecdsa-sha2-nistp384-cert-v01@openssh.com", G_MAXULONG, NULL },
	{ "ecdsa-sha2-nistp521-cert-v01@openssh.com", G_MAXULONG, NULL },
	/* no new signatures/algorithms */
	{ "rsa-sha2-256", G_MAXULONG, NULL },
	{ "rsa-sha2-512", G_MAXULONG, NULL },
	{ "ssh-ed25519", G_MAXULONG, NULL },
	{ "ssh-ed25519-cert-v01@openssh.com", G_MAXULONG, NULL },

	/* terminator */
	{ NULL, 0, NULL }
};

/* unknown algorithms */
static const struct alg algs_generate_unknown[] = {
	{ NULL, CKK_RSA, "NIST P-256" },
	{ NULL, CKK_DSA, "NIST P-384" },
	{ NULL, CKK_ECDSA, "NIST P-512" }, /* 512 is not a valid size! */
	{ NULL, CKK_ECDSA, "" }, /* missing curve */

	/* terminator */
	{ NULL, 0, NULL }
};

static const struct alg curves[] = {
	{ "ecdsa-sha2-nistp256", CKK_EC, "NIST P-256" },
	{ "ecdsa-sha2-nistp384", CKK_EC, "NIST P-384" },
	{ "ecdsa-sha2-nistp521", CKK_EC, "NIST P-521" },

	/* terminator */
	{ NULL, 0, NULL }
};

typedef struct {
	const struct alg	*algs_known;
	const struct alg	*algs_parse_unknown;
	const struct alg	*algs_generate_unknown;
	const struct alg	*curves;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	test->algs_known = algs_known;
	test->algs_parse_unknown = algs_parse_unknown;
	test->algs_generate_unknown = algs_generate_unknown;
	test->curves = curves;
}

static void
teardown (Test *test, gconstpointer unused)
{
}

static void
test_parse (Test *test, gconstpointer unused)
{
	const struct alg *a;
	gulong alg_id;

	/* known */
	for (a = test->algs_known; a->name != NULL; a++) {
		alg_id = gkd_ssh_agent_proto_keytype_to_algo(a->name);
		g_assert (a->id == alg_id);
	}

	g_assert (a->id == 0);

	/* we do not recognize nor fail with the unknown */
	for (a = test->algs_parse_unknown; a->name != NULL; a++) {
		alg_id = gkd_ssh_agent_proto_keytype_to_algo(a->name);
		g_assert (a->id == alg_id);
	}

	g_assert (a->id == 0);
}

static void
test_generate (Test *test, gconstpointer unused)
{
	const struct alg *a;
	const gchar *alg_name;

	/* known */
	for (a = test->algs_known; a->name != NULL; a++) {
		alg_name = gkd_ssh_agent_proto_algo_to_keytype(a->id, a->ec_curve);
		g_assert (strcmp(a->name, alg_name) == 0);
	}

	/* we do not recognize nor fail with the unknown */
	for (a = test->algs_generate_unknown; a->ec_curve != NULL; a++) {
		alg_name = gkd_ssh_agent_proto_algo_to_keytype(a->id, a->ec_curve);
		g_assert (alg_name == NULL); /* NULL return */
	}
}

static void
test_curve_from_ssh (Test *test, gconstpointer unused)
{
	const struct alg *a;
	const gchar *alg_name;

	/* known */
	for (a = test->curves; a->name != NULL; a++) {
		alg_name = gkd_ssh_agent_proto_curve_to_keytype(a->ec_curve);
		g_assert (strcmp(a->name, alg_name) == 0);
	}

	alg_name = gkd_ssh_agent_proto_curve_to_keytype("NIST P-unknown");
	g_assert (alg_name == NULL);
}

static void
test_ssh_from_curve (Test *test, gconstpointer unused)
{
	const struct alg *a;
	const gchar *curve_name;

	/* known */
	for (a = test->curves; a->name != NULL; a++) {
		curve_name = gkd_ssh_agent_proto_keytype_to_curve(a->name);
		g_assert (strcmp(a->ec_curve, curve_name) == 0);
	}

	curve_name = gkd_ssh_agent_proto_keytype_to_curve("ecdsa-sha2-nistpunknown");
	g_assert (curve_name == NULL);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/daemon/ssh-agent/keytypes/parse", Test, NULL, setup, test_parse, teardown);
	g_test_add ("/daemon/ssh-agent/keytypes/generate", Test, NULL, setup, test_generate, teardown);
	g_test_add ("/daemon/ssh-agent/keytypes/curve_from_ssh", Test, NULL, setup, test_curve_from_ssh, teardown);
	g_test_add ("/daemon/ssh-agent/keytypes/ssh_from_curve", Test, NULL, setup, test_ssh_from_curve, teardown);

	return g_test_run ();
}
