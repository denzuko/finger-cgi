/*
 * test.h — minimal xUnit framework for finger-cgi
 *
 * SPDX-License-Identifier: BSD-2-Clause
 * Da Planet Security / denzuko <denzuko@dapla.net>
 */

#ifndef TEST_H
#define TEST_H

#include <stdio.h>

static int _tests_run    = 0;
static int _tests_passed = 0;
static int _tests_failed = 0;

#define ASSERT(cond) \
    do { \
        _tests_run++; \
        if (cond) { \
            _tests_passed++; \
            printf("  %-52s PASS\n", __func__); \
        } else { \
            _tests_failed++; \
            printf("  %-52s FAIL (%s:%d)\n", __func__, __FILE__, __LINE__); \
        } \
    } while (0)

#define TEST(name) static void name(void)
#define RUN(name)  do { name(); } while (0)

static int xunit_summary(void)
{
    printf("\n%d/%d passed\n", _tests_passed, _tests_run);
    return (_tests_failed > 0) ? 1 : 0;
}

#endif /* TEST_H */
