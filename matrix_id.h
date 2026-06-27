/*
 * matrix_id.h — net.matrix CMDB identity strings
 *
 * Embedded into every binary at compile time via volatile const char[].
 * Extractable without execution: strings(1), objdump -s, forensic tools.
 * Used for change item attribution and provenance attestation.
 *
 * DPS-constant values are defined here.
 * Per-binary values are injected by nob.c via -D flags:
 *   -DMATRIX_APPLICATION="..."
 *   -DMATRIX_ROLE="..."
 *   -DMATRIX_VERSION="..."
 *   -DMATRIX_ENVIRONMENT="..."
 *
 * IANA PEN: 42387  D&B DUNS: 039-271-257
 *
 * Da Planet Security / denzuko <denzuko@dapla.net>
 * BSD 2-Clause License
 */

#ifndef MATRIX_ID_H
#define MATRIX_ID_H

/* Per-binary overrides — nob.c must supply all four */
#ifndef MATRIX_APPLICATION
#  define MATRIX_APPLICATION "unknown"
#endif
#ifndef MATRIX_ROLE
#  define MATRIX_ROLE "unknown"
#endif
#ifndef MATRIX_VERSION
#  define MATRIX_VERSION "0.0.0"
#endif
#ifndef MATRIX_ENVIRONMENT
#  define MATRIX_ENVIRONMENT "production"
#endif

/*
 * volatile prevents the compiler eliding unused-looking strings at -O2.
 * C99 has no __attribute__((used)); volatile const is the portable path.
 * One TU must include this header in a non-static context to guarantee
 * the strings survive linking — main.c is the canonical owner.
 */
static volatile const char MATRIX_ID_ORGANIZATION[] =
    "net.matrix.organization=daplanet";
static volatile const char MATRIX_ID_ORGUNIT[] =
    "net.matrix.orgunit=dps";
static volatile const char MATRIX_ID_OWNER[] =
    "net.matrix.owner=FC13F74B@matrix.net";
static volatile const char MATRIX_ID_OID[] =
    "net.matrix.oid=iso.org.dod.internet.42387";
static volatile const char MATRIX_ID_DUNS[] =
    "net.matrix.duns=iso.org.duns.039271257";
static volatile const char MATRIX_ID_CUSTOMER[] =
    "net.matrix.customer=PVT-01";
static volatile const char MATRIX_ID_COSTCENTER[] =
    "net.matrix.costcenter=INT-01";

/* Per-binary — resolved at compile time from -D flags */
static volatile const char MATRIX_ID_APPLICATION[] =
    "net.matrix.application=" MATRIX_APPLICATION;
static volatile const char MATRIX_ID_ROLE[] =
    "net.matrix.role=" MATRIX_ROLE;
static volatile const char MATRIX_ID_VERSION[] =
    "net.matrix.version=" MATRIX_VERSION;
static volatile const char MATRIX_ID_ENVIRONMENT[] =
    "net.matrix.environment=" MATRIX_ENVIRONMENT;

#endif /* MATRIX_ID_H */
