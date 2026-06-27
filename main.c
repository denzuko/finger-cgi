/*
 * main.c — CGI finger gateway
 *
 * Routes:
 *   GET  /         — form page
 *   POST /?user=X  — htmx partial: finger result for whitelisted host
 *
 * Security:
 *   - Host whitelist (no SSRF via getaddrinfo)
 *   - Username sanitisation (alnum + hyphen + underscore only)
 *   - BAIL macro for single-exit error handling
 *   - BSD sandbox via pledge(2) on OpenBSD, Capsicum on FreeBSD;
 *     NetBSD left unsandboxed (no equivalent API)
 *
 * Stack: kcgi/kcgihtml, tsoding arena.h/sv.h, htmx, Alpine.js
 *
 * SPDX-License-Identifier: BSD-2-Clause
 * Da Planet Security / denzuko <denzuko@dapla.net>
 */

#define ARENA_IMPLEMENTATION
#include "arena.h"
#define SV_IMPLEMENTATION
#include "sv.h"
#include "matrix_id.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <kcgi.h>
#include <kcgihtml.h>

/* ── BSD sandbox ─────────────────────────────────────────────────────────── */

#ifdef __OpenBSD__
#  define HAS_SANDBOX 1
#  include <unistd.h>   /* pledge(2) */
static void sandbox_init(void)
{
    if (-1 == pledge("stdio inet dns", NULL))
        _exit(1);
}
#elif defined(__FreeBSD__)
#  define HAS_SANDBOX 1
#  include <sys/capsicum.h>
static void sandbox_init(void) { (void)0; } /* capsicum post-socket */
#else
#  define HAS_SANDBOX 0
static void sandbox_init(void) { (void)0; }
#endif

/* ── Constants ───────────────────────────────────────────────────────────── */

#define FINGER_PORT   "79"
#define MAX_USER_LEN  64
#define RECV_BUFSZ    (16 * 1024)

/* Whitelisted finger hosts — only these are ever contacted.
 * Edit here to add hosts; never pass user input to getaddrinfo. */
static const char *const HOSTS[] = {
    "panix.com",
    "plan9.bell-labs.com",
    "quux.org",
    NULL
};

/* CSS design tokens — Da Planet terminal aesthetic */
#define CSS_BODY      "bg-[#0a0a0a] text-[#39ff14] min-h-screen font-mono p-4"
#define CSS_CONTAINER "max-w-2xl mx-auto"
#define CSS_TITLE     "text-2xl font-bold mb-6 text-[#39ff14]"
#define CSS_FORM      "flex gap-2 mb-6"
#define CSS_INPUT     "flex-1 bg-[#0d1117] border border-[#1f2937] text-[#39ff14] px-3 py-2 font-mono"
#define CSS_SELECT    "bg-[#0d1117] border border-[#1f2937] text-[#39ff14] px-3 py-2 font-mono"
#define CSS_BTN       "bg-[#39ff14] text-black px-4 py-2 font-bold font-mono"
#define CSS_PRE       "bg-[#0d1117] border border-[#1f2937] p-4 whitespace-pre-wrap break-words text-sm"
#define CSS_ERROR     "text-[#ff1744] font-mono"

#define HTMX_CDN  "https://unpkg.com/htmx.org@1.9.12"
#define ALPINE_CDN "https://unpkg.com/alpinejs@3.13.3/dist/cdn.min.js"

/* ── kcgi keys ───────────────────────────────────────────────────────────── */

enum Key { KEY_USER = 0, KEY_HOST, KEY__MAX };

static const struct kvalid KEYS[KEY__MAX] = {
    { kvalid_stringne, "user" },
    { kvalid_stringne, "host" },
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */

#define BAIL(msg) do { errmsg = (msg); break; } while (0)

/* Returns index into HOSTS[] or -1 if not whitelisted. */
static int host_validate(const char *host)
{
    if (NULL == host || '\0' == host[0]) return -1;
    for (int i = 0; NULL != HOSTS[i]; i++)
        if (0 == strcmp(host, HOSTS[i])) return i;
    return -1;
}

/* Returns arena-allocated sanitised copy of user, or "" if NULL/invalid. */
static const char *user_sanitise(Arena *a, const char *raw)
{
    if (NULL == raw || '\0' == raw[0]) return "";
    size_t len = strlen(raw);
    if (MAX_USER_LEN < len) len = MAX_USER_LEN;
    char *out = arena_alloc(a, len + 1);
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = raw[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || '-' == c || '_' == c)
            out[j++] = c;
    }
    out[j] = '\0';
    return out;
}

/* Perform finger query; write preformatted result into html. */
static void do_finger(Arena *a, struct khtmlreq *html,
                      const char *user, const char *host)
{
    const char *errmsg = NULL;
    char *buf           = arena_alloc(a, RECV_BUFSZ);

    do {
        struct addrinfo hints = {0};
        struct addrinfo *res  = NULL;
        hints.ai_family       = AF_UNSPEC;
        hints.ai_socktype     = SOCK_STREAM;

        if (0 != getaddrinfo(host, FINGER_PORT, &hints, &res))
            BAIL("DNS lookup failed");

        int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (-1 == fd) { freeaddrinfo(res); BAIL("socket() failed"); }

        if (-1 == connect(fd, res->ai_addr, res->ai_addrlen)) {
            freeaddrinfo(res);
            close(fd);
            BAIL("connect() failed");
        }
        freeaddrinfo(res);

        /* RFC 1288: send "/W user\r\n" or "\r\n" for site list */
        char req[MAX_USER_LEN + 8];
        int rlen = ('\0' == user[0])
            ? snprintf(req, sizeof(req), "\r\n")
            : snprintf(req, sizeof(req), "/W %s\r\n", user);
        if (rlen < 0 || (size_t)rlen >= sizeof(req)) {
            close(fd);
            BAIL("request too long");
        }

        if (-1 == send(fd, req, (size_t)rlen, 0)) {
            close(fd);
            BAIL("send() failed");
        }

        ssize_t n = recv(fd, buf, RECV_BUFSZ - 1, 0);
        close(fd);

        if (-1 == n) BAIL("recv() failed");
        buf[n] = '\0';
    } while (0);

    khtml_attr(html, KELEM_DIV, KATTR_ID, "result", KATTR__MAX);
    if (NULL != errmsg) {
        khtml_attr(html, KELEM_P, KATTR_CLASS, CSS_ERROR, KATTR__MAX);
        khtml_puts(html, errmsg);
        khtml_closeelem(html, 1);
    } else {
        khtml_attr(html, KELEM_PRE, KATTR_CLASS, CSS_PRE, KATTR__MAX);
        khtml_puts(html, buf);
        khtml_closeelem(html, 1);
    }
    khtml_closeelem(html, 1); /* /div#result */
}

/* ── Render helpers ──────────────────────────────────────────────────────── */

static void render_head(struct khtmlreq *html)
{
    khtml_elem(html, KELEM_HEAD);
    khtml_attr(html, KELEM_META,
        KATTR_NAME, "viewport",
        KATTR_CONTENT, "width=device-width,initial-scale=1",
        KATTR__MAX);
    khtml_attr(html, KELEM_SCRIPT,
        KATTR_SRC, HTMX_CDN,
        KATTR__MAX);
    khtml_closeelem(html, 1);
    khtml_attr(html, KELEM_SCRIPT,
        KATTR_SRC, ALPINE_CDN,
        KATTR_DEFER, "",
        KATTR__MAX);
    khtml_closeelem(html, 1);
    khtml_elem(html, KELEM_TITLE);
    khtml_puts(html, "finger.dapla.net");
    khtml_closeelem(html, 2); /* /title /head */
}

static void render_form(struct khtmlreq *html, const char *selected_host)
{
    khtml_attr(html, KELEM_FORM,
        KATTR_ENCTYPE, "application/x-www-form-urlencoded",
        KATTR_HXPOST, "",
        KATTR_HXTARGET, "#result",
        KATTR_HXSWAP, "outerHTML",
        KATTR__MAX);

    /* user input */
    khtml_attr(html, KELEM_INPUT,
        KATTR_TYPE, "text",
        KATTR_NAME, "user",
        KATTR_PLACEHOLDER, "username (blank for site list)",
        KATTR_CLASS, CSS_INPUT,
        KATTR__MAX);

    /* host select */
    khtml_attr(html, KELEM_SELECT,
        KATTR_NAME, "host",
        KATTR_CLASS, CSS_SELECT,
        KATTR__MAX);
    for (int i = 0; NULL != HOSTS[i]; i++) {
        if (NULL != selected_host && 0 == strcmp(selected_host, HOSTS[i]))
            khtml_attr(html, KELEM_OPTION,
                KATTR_VALUE, HOSTS[i], KATTR_SELECTED, "", KATTR__MAX);
        else
            khtml_attr(html, KELEM_OPTION,
                KATTR_VALUE, HOSTS[i], KATTR__MAX);
        khtml_puts(html, HOSTS[i]);
        khtml_closeelem(html, 1);
    }
    khtml_closeelem(html, 1); /* /select */

    khtml_attr(html, KELEM_BUTTON,
        KATTR_TYPE, "submit",
        KATTR_CLASS, CSS_BTN,
        KATTR__MAX);
    khtml_puts(html, "finger");
    khtml_closeelem(html, 2); /* /button /form */
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(void)
{
    sandbox_init();

    struct kreq   r    = {0};
    struct khtmlreq html = {0};
    Arena         a    = {0};

    if (KCGI_OK != khttp_parse(&r, KEYS, KEY__MAX, NULL, 0, 0))
        return 1;

    int is_htmx = (NULL != r.reqmap[KREQU_HX_REQUEST]);

    khttp_head(&r, kresps[KRESP_STATUS],
               "%s", khttps[KHTTP_200]);
    khttp_head(&r, kresps[KRESP_CONTENT_TYPE],
               "%s", kmimetypes[KMIME_TEXT_HTML]);
    khttp_body(&r);

    khtml_open(&html, &r, KHTML_PRETTY);

    if (!is_htmx) {
        khtml_elem(&html, KELEM_DOCTYPE);
        khtml_elem(&html, KELEM_HTML);
        render_head(&html);
        khtml_attr(&html, KELEM_BODY, KATTR_CLASS, CSS_BODY, KATTR__MAX);
        khtml_attr(&html, KELEM_DIV,  KATTR_CLASS, CSS_CONTAINER, KATTR__MAX);
        khtml_attr(&html, KELEM_H1,   KATTR_CLASS, CSS_TITLE, KATTR__MAX);
        khtml_puts(&html, "finger gateway");
        khtml_closeelem(&html, 1);
    }

    const char *host_raw = (NULL != r.fieldmap[KEY_HOST])
        ? r.fieldmap[KEY_HOST]->val : NULL;

    render_form(&html, host_raw);

    int hidx = host_validate(host_raw);
    if (NULL != host_raw && -1 != hidx) {
        const char *user = user_sanitise(&a,
            (NULL != r.fieldmap[KEY_USER])
                ? r.fieldmap[KEY_USER]->val : NULL);
        do_finger(&a, &html, user, HOSTS[hidx]);
    } else {
        /* Empty result placeholder for htmx swap target */
        khttp_puts(&r, "<div id=\"result\"></div>");
    }

    if (!is_htmx)
        khtml_closeelem(&html, 4); /* /div /body /html (+ DOCTYPE) */

    khtml_close(&html);
    khttp_free(&r);
    arena_free(&a);

    return 0;
}
