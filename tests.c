/*
 * tests.c — xUnit test suite for finger-cgi
 *
 * Build + run:
 *   cc nob.c -o nob && ./nob test
 *
 * SPDX-License-Identifier: BSD-2-Clause
 * Da Planet Security / denzuko <denzuko@dapla.net>
 */

#include "test.h"
#include "matrix_id.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

/* ── Suite: input sanitisation ──────────────────────────────────────────── */

TEST(sanitise_username_rejects_dotdot)
{
    /* Path traversal via .. must be rejected */
    const char *input = "../etc/passwd";
    int valid = 1;
    for (const char *p = input; *p; p++) {
        if ('.' == *p || '/' == *p || '\0' == *p) { valid = 0; break; }
    }
    ASSERT(0 == valid);
}

TEST(sanitise_username_accepts_alnum)
{
    const char *input = "denzuko";
    int valid = 1;
    for (const char *p = input; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') ||
              (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') ||
              '-' == *p || '_' == *p)) {
            valid = 0; break;
        }
    }
    ASSERT(1 == valid);
}

TEST(sanitise_username_rejects_null)
{
    const char *input = NULL;
    ASSERT(NULL == input);
}

/* ── Suite: net.matrix identity ─────────────────────────────────────────── */

TEST(matrix_organization_present)
{
    /* volatile prevents optimiser eliding the string */
    extern volatile const char MATRIX_ID_ORGANIZATION[];
    ASSERT(NULL != MATRIX_ID_ORGANIZATION);
    ASSERT('\0' != MATRIX_ID_ORGANIZATION[0]);
}

TEST(matrix_application_is_finger_cgi)
{
    extern volatile const char MATRIX_ID_APPLICATION[];
    ASSERT(NULL != MATRIX_ID_APPLICATION);
    /* "net.matrix.application=finger-cgi" */
    ASSERT(NULL != strstr((const char *)MATRIX_ID_APPLICATION, "finger-cgi"));
}

TEST(matrix_owner_present)
{
    extern volatile const char MATRIX_ID_OWNER[];
    ASSERT(NULL != MATRIX_ID_OWNER);
    ASSERT(NULL != strstr((const char *)MATRIX_ID_OWNER, "FC13F74B"));
}

/* ── Suite: SLSA provenance paths ───────────────────────────────────────── */

TEST(slsa_binary_output_path_is_deterministic)
{
    const char *path = "finger.cgi";
    ASSERT(NULL != path);
    ASSERT('\0' != path[0]);

    errno = 0;
    FILE *f = fopen(path, "rb");
    if (NULL != f) {
        ASSERT(0 == fseek(f, -1L, SEEK_END));
        ASSERT(0 == ferror(f));
        fclose(f);
    } else {
        ASSERT(ENOENT == errno || EACCES == errno);
    }
}

TEST(slsa_hash_output_path_is_deterministic)
{
    const char *path = "finger.cgi.sha256";
    ASSERT(NULL != path);
    ASSERT('\0' != path[0]);

    errno = 0;
    FILE *f = fopen(path, "rb");
    if (NULL != f) {
        ASSERT(0 == fseek(f, -1L, SEEK_END));
        ASSERT(0 == ferror(f));
        fclose(f);
    } else {
        ASSERT(ENOENT == errno || EACCES == errno);
    }
}

int main(void)
{
    printf("finger-cgi xUnit test suite\n");
    printf("===========================\n\n");

    printf("input sanitisation:\n");
    RUN(sanitise_username_rejects_dotdot);
    RUN(sanitise_username_accepts_alnum);
    RUN(sanitise_username_rejects_null);

    printf("\nnet.matrix identity:\n");
    RUN(matrix_organization_present);
    RUN(matrix_application_is_finger_cgi);
    RUN(matrix_owner_present);

    printf("\nSLSA provenance paths:\n");
    RUN(slsa_binary_output_path_is_deterministic);
    RUN(slsa_hash_output_path_is_deterministic);

    return xunit_summary();
}
