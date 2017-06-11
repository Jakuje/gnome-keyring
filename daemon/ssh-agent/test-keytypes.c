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
	GQuark		 oid;
};

/* can't use Quarks as a static initializers */

/* known algorithms */
static struct alg algs_known[] = {
	{ "ssh-rsa", CKK_RSA, 0 },
	{ "ssh-dss", CKK_DSA, 0 },
	{ "ecdsa-sha2-nistp256", CKK_EC, 0 }, /* OID_ANSI_SECP256R1 */
	{ "ecdsa-sha2-nistp384", CKK_EC, 0 }, /* OID_ANSI_SECP384R1 */
	{ "ecdsa-sha2-nistp521", CKK_EC, 0 }, /* OID_ANSI_SECP521R1 */

	/* terminator */
	{ NULL, 0, 0 }
};

/* unknown algorithms */
static struct alg algs_parse_unknown[] = {
	/* no certificates */
	{ "ssh-rsa-cert-v01@openssh.com", G_MAXULONG, 0 },
	{ "ssh-dss-cert-v01@openssh.com", G_MAXULONG, 0 },
	{ "ecdsa-sha2-nistp256-cert-v01@openssh.com", G_MAXULONG, 0 },
	{ "ecdsa-sha2-nistp384-cert-v01@openssh.com", G_MAXULONG, 0 },
	{ "ecdsa-sha2-nistp521-cert-v01@openssh.com", G_MAXULONG, 0 },
	/* no new signatures/algorithms */
	{ "rsa-sha2-256", G_MAXULONG, 0 },
	{ "rsa-sha2-512", G_MAXULONG, 0 },
	{ "ssh-ed25519", G_MAXULONG, 0 },
	{ "ssh-ed25519-cert-v01@openssh.com", G_MAXULONG, 0 },

	/* terminator */
	{ NULL, 0, 0 }
};

/* unknown algorithms */
static struct alg algs_generate_unknown[] = {
	{ NULL, CKK_RSA, 0 }, /* OID_ANSI_SECP256R1 */
	{ NULL, CKK_DSA, 0 }, /* OID_ANSI_SECP384R1 */
	{ NULL, CKK_ECDSA, 0 }, /* missing curve */

	/* terminator */
	{ NULL, 0, 0 }
};

static struct alg curves[] = {
	{ "ecdsa-sha2-nistp256", CKK_EC, 0 }, /* OID_ANSI_SECP256R1 */
	{ "ecdsa-sha2-nistp384", CKK_EC, 0 }, /* OID_ANSI_SECP384R1 */
	{ "ecdsa-sha2-nistp521", CKK_EC, 0 }, /* OID_ANSI_SECP521R1 */

	/* terminator */
	{ NULL, 0, 0 }
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
	gkd_ssh_agent_proto_init_quarks ();

	algs_known[2].oid = OID_ANSI_SECP256R1;
	algs_known[3].oid = OID_ANSI_SECP384R1;
	algs_known[4].oid = OID_ANSI_SECP521R1;
	test->algs_known = algs_known;
	test->algs_parse_unknown = algs_parse_unknown;

	algs_generate_unknown[0].oid = OID_ANSI_SECP256R1;
	algs_generate_unknown[1].oid = OID_ANSI_SECP384R1;
	test->algs_generate_unknown = algs_generate_unknown;
	curves[0].oid = OID_ANSI_SECP256R1;
	curves[1].oid = OID_ANSI_SECP384R1;
	curves[2].oid = OID_ANSI_SECP521R1;
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
		alg_name = gkd_ssh_agent_proto_algo_to_keytype(a->id, a->oid);
		g_assert (strcmp(a->name, alg_name) == 0);
	}

	/* we do not recognize nor fail with the unknown */
	for (a = test->algs_generate_unknown; a->oid != 0; a++) {
		alg_name = gkd_ssh_agent_proto_algo_to_keytype(a->id, a->oid);
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
		alg_name = gkd_ssh_agent_proto_oid_to_keytype(a->oid);
		g_assert (strcmp(a->name, alg_name) == 0);
	}

	alg_name = gkd_ssh_agent_proto_oid_to_keytype(65000);
	g_assert (alg_name == NULL);
}

static void
test_ssh_from_curve (Test *test, gconstpointer unused)
{
	const struct alg *a;
	GQuark oid;

	/* known */
	for (a = test->curves; a->name != NULL; a++) {
		oid = gkd_ssh_agent_proto_keytype_to_oid(a->name);
		g_assert (a->oid ==oid);
	}

	oid = gkd_ssh_agent_proto_keytype_to_oid("ecdsa-sha2-nistpunknown");
	g_assert (oid == 0);
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
