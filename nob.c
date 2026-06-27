/*
 * nob.c — build driver for finger-cgi
 *
 * Bootstrap:
 *   cc nob.c -o nob
 *
 * Targets:
 *   ./nob           — build finger.cgi
 *   ./nob test      — build + run tests
 *   ./nob install   — deploy to ~/public_html/cgi-bin/
 *   ./nob clean     — remove build artefacts
 *
 * SPDX-License-Identifier: BSD-2-Clause
 * Da Planet Security / denzuko <denzuko@dapla.net>
 */

#define NOB_IMPLEMENTATION
#include "nob.h"

#define TARGET    "finger.cgi"
#define TEST_BIN  "build/tests"
#define VERSION   "1.0.0"

#define CFLAGS \
    "-std=c99", "-O2", "-Wall", "-Wextra", "-Wpedantic", \
    "-Wno-unused-parameter", "-I."

#define MATRIX_FLAGS \
    "-DMATRIX_APPLICATION=\"finger-cgi\"", \
    "-DMATRIX_ROLE=\"cgi-gateway\"",       \
    "-DMATRIX_VERSION=\"" VERSION "\"",           \
    "-DMATRIX_ENVIRONMENT=\"production\""

static bool build(void)
{
    nob_mkdir_if_not_exists("build");
    Nob_Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cmd_append(&cmd, CFLAGS, MATRIX_FLAGS);
    nob_cmd_append(&cmd, "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong");
    nob_cc_output(&cmd, TARGET);
    nob_cmd_append(&cmd, "main.c");
    nob_cmd_append(&cmd, "-lkcgi", "-lkcgihtml", "-lz", "-lcrypt");
    nob_log(NOB_INFO, "building %s", TARGET);
    return nob_cmd_run(&cmd);
}

static bool build_tests(void)
{
    nob_mkdir_if_not_exists("build");
    Nob_Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cmd_append(&cmd, CFLAGS, MATRIX_FLAGS);
    nob_cc_output(&cmd, TEST_BIN);
    nob_cmd_append(&cmd, "tests.c");
    nob_log(NOB_INFO, "building tests");
    if (!nob_cmd_run(&cmd)) return false;
    cmd = (Nob_Cmd){0};
    nob_cmd_append(&cmd, TEST_BIN);
    nob_log(NOB_INFO, "running tests");
    return nob_cmd_run(&cmd);
}

static void do_clean(void)
{
    remove(TARGET);
    remove(TEST_BIN);
    nob_log(NOB_INFO, "clean");
}

static void do_install(void)
{
    const char *home = getenv("HOME");
    if (!home) { nob_log(NOB_ERROR, "HOME not set"); return; }
    char dest[512];
    snprintf(dest, sizeof(dest), "%s/public_html/cgi-bin/%s", home, TARGET);
    Nob_Cmd cmd = {0};
    nob_cmd_append(&cmd, "install", "-m", "0755", TARGET, dest);
    nob_log(NOB_INFO, "installing to %s", dest);
    nob_cmd_run(&cmd);
}

int main(int argc, char **argv)
{
    NOB_GO_REBUILD_URSELF(argc, argv);
    if (argc < 2 || strcmp(argv[1], "build") == 0) { build(); return 0; }
    if (strcmp(argv[1], "test")    == 0) { return build_tests() ? 0 : 1; }
    if (strcmp(argv[1], "install") == 0) { build(); do_install(); return 0; }
    if (strcmp(argv[1], "clean")   == 0) { do_clean(); return 0; }
    nob_log(NOB_ERROR, "unknown target: %s", argv[1]);
    return 1;
}
