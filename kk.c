/* kk.c — single-file, zero-dependency Windows coding agent (Win32 + CRT only,
 * MSVC /std:c11). Everything is static except wmain, so the optimizer sees the
 * whole program. Sections, in dependency order:
 *   1 basics    buf / arena / str slices / dyn arrays
 *   2 json      arena-backed parser (zero-copy slices) + serializers
 *   3 utf8      decode / encode / display width (CJK + emoji)
 *   4 terminal  console VT setup, output lock, WinHTTP transport
 *   5 markdown  streaming renderer (append-only painter)
 *   6 protocol  SSE framing + chat-completions delta assembly
 *   7 tools     read / write / bash / find / grep
 *   8 session   JSONL persistence, config, system prompt
 *   9 ui        line editor, slash commands, AGENTS.md
 *  10 agent     turn loop + wmain
 *
 * Memory rules: one growable buf type; a bump arena per model request (no
 * frees on the streaming path); JSON parses to (ptr,len) slices into a buffer
 * the caller keeps alive; strdup only for what outlives the turn.
 *
 * Display: what the model sees reaches the screen, with one deliberate
 * exception — the body a quiet tool (read, find, grep) returns stays in the
 * model's view only, because 2000 lines of file would bury the conversation.
 * Their errors are still shown, and the session log holds every byte sent.
 */

/* Trim windows.h: console/process/thread/WinHTTP only — skipping GDI, crypto,
 * OLE, shell and winsock cuts compile time. */
#define WIN32_LEAN_AND_MEAN
#define NOGDI
#define NOCRYPT
#include <windows.h>
#include <winhttp.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_M_X64)
#include <emmintrin.h> /* SSE2 is x86-64 baseline, not an /arch option */
#endif

/* fff.h is cbindgen output for GCC targets: neutralize GCC attributes
 * (e.g. __attribute__((deprecated(...)))) for MSVC */
#define __attribute__(x)
#include "fff.h" /* Rust fuzzy finder/grep cdylib API (types only; functions
                  * resolve through LoadLibrary at runtime) */
#define KK_VERSION "0.1.0"

/* ==========================================================================
 * 1. basics
 * ========================================================================== */

static void fatal(const char *fmt, ...)
{
    va_list ap;
    fputs("kk: fatal: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        fatal("out of memory (%zu bytes)", n);
    return p;
}

static void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p)
        fatal("out of memory (%zu x %zu bytes)", n, sz);
    return p;
}

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q)
        fatal("out of memory (%zu bytes)", n);
    return q;
}

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = xmalloc(n);
    memcpy(d, s, n);
    return d;
}

static char *xstrndup(const char *s, size_t n)
{
    char *d = xmalloc(n + 1);
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

/* Heap copy of s, or of fallback when s is missing. */
static char *xstr_or(const char *s, const char *fallback)
{
    return xstrdup(s ? s : fallback);
}

/* Environment lookup via Win32 (CRT getenv is deprecated under /W4).
 * Returns a heap string or NULL; caller frees. */
static char *env_get(const char *name)
{
    DWORD n = GetEnvironmentVariableA(name, NULL, 0);
    if (n == 0)
        return NULL;
    char *v = xmalloc(n);
    DWORD got = GetEnvironmentVariableA(name, v, n);
    if (got == 0 || got >= n) {
        free(v);
        return NULL;
    }
    return v;
}

/* Decimal digits at *pp, advancing past them (an empty run parses to 0). */
static int64_t str_to_i64(const char **pp)
{
    int64_t v = 0;
    while (**pp >= '0' && **pp <= '9')
        v = v * 10 + *(*pp)++ - '0';
    return v;
}

/* Environment integer, or fallback when unset, unparsable, or below `min`.
 * Callers that read it on a hot path keep their own cached static. */
static int64_t env_i64(const char *name, int64_t min, int64_t fallback)
{
    char *raw = env_get(name);
    if (!raw)
        return fallback;
    const char *p = raw; /* str_to_i64 advances its cursor: keep the block */
    int64_t v = str_to_i64(&p);
    free(raw);
    return v >= min ? v : fallback;
}

static char *xasprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0)
        fatal("format error");
    char *s = xmalloc((size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf(s, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return s;
}

/* --- growable byte buffer -------------------------------------------- */

struct buf {
    char *p;
    size_t len;
    size_t cap;
};

#define BUF_INIT \
    { 0 }

/* Invariant: b->p[b->len] is always '\0', so callers may strlen() a buf's
 * bytes directly; reserve() sizes for the NUL too. */
static void buf_reserve(struct buf *b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap)
        return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra + 1)
        cap *= 2;
    b->p = xrealloc(b->p, cap);
    b->cap = cap;
}

static void buf_append_n(struct buf *b, const char *s, size_t n)
{
    if (!n) {
        buf_reserve(b, 0);
        b->p[b->len] = '\0';
        return;
    }
    buf_reserve(b, n);
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void buf_appendc(struct buf *b, char c)
{
    buf_reserve(b, 1);
    b->p[b->len++] = c;
    b->p[b->len] = '\0';
}

static void buf_appends(struct buf *b, const char *s)
{
    buf_append_n(b, s, strlen(s));
}

/* Append n spaces (row indent, cell padding) in 64-byte chunks. */
static void buf_append_spaces(struct buf *b, size_t n)
{
    static const char spaces[] =
        "                                                                ";
    while (n) {
        size_t take = n < sizeof spaces - 1 ? n : sizeof spaces - 1;
        buf_append_n(b, spaces, take);
        n -= take;
    }
}

/* Append a string literal without a runtime strlen (sizeof carries its
 * length; the "" concatenation forces lit to be a literal). */
#define buf_append_lit(b, lit) buf_append_n((b), "" lit, sizeof(lit) - 1)

/* Format into b's spare capacity in ONE pass, appending. UCRT reports the
 * would-be length even when truncated, so a small guess costs a retry and
 * only the rare big line pays two passes. */
static void buf_append_vf(struct buf *b, const char *fmt, va_list ap0)
{
    for (;;) {
        size_t avail = b->cap > b->len ? b->cap - b->len : 0;
        if (avail < 64) {
            buf_reserve(b, 256); /* leaves at least 257 bytes of room */
            avail = b->cap - b->len;
        }
        va_list ap;
        va_copy(ap, ap0);
        int n = vsnprintf(b->p + b->len, avail, fmt, ap);
        va_end(ap);
        if (n < 0) {
            b->p[b->len] = '\0'; /* keep the buf NUL invariant */
            return;
        }
        if ((size_t)n < avail) {
            b->len += (size_t)n;
            b->p[b->len] = '\0';
            return;
        }
        buf_reserve(b, (size_t)n + 1); /* did not fit: make room, format once */
    }
}

static void buf_appendf(struct buf *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    buf_append_vf(b, fmt, ap);
    va_end(ap);
}

static size_t u8_encode(uint32_t cp, char *tmp);

/* Append one unicode codepoint encoded as UTF-8. */
static void buf_append_cp(struct buf *b, uint32_t cp)
{
    char tmp[4];
    buf_append_n(b, tmp, u8_encode(cp, tmp));
}

static void buf_free(struct buf *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

static void buf_reset(struct buf *b)
{
    b->len = 0;
}

/* Take ownership of the bytes as a nul-terminated heap string. */
static char *buf_detach(struct buf *b)
{
    buf_reserve(b, 1);
    b->p[b->len] = '\0';
    char *s = b->p;
    b->p = NULL;
    b->len = b->cap = 0;
    return s;
}

/* --- string slices ---------------------------------------------------- */

struct str {
    const char *p;
    size_t n;
};

static struct str str_from_c(const char *s)
{
    struct str r = { s, s ? strlen(s) : 0 };
    return r;
}

static int str_eq(struct str a, struct str b)
{
    return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, a.n) == 0);
}

static int str_eqc(struct str a, const char *c)
{
    return str_eq(a, str_from_c(c));
}

static char *str_dupz(struct str s)
{
    return xstrndup(s.p, s.n);
}

/* Bounded substring search: nd (m bytes) inside h[0..n), or NULL. A
 * single-byte needle is a plain memchr — the read tool searches for '\n' on
 * every line of every page. */
static char *mem_find(const char *h, size_t n, const char *nd, size_t m)
{
    if (m == 1)
        return (char *)memchr(h, (unsigned char)nd[0], n);
    while (n >= m) {
        const char *hit = memchr(h, nd[0], n - m + 1);
        if (!hit)
            return NULL;
        if (memcmp(hit, nd, m) == 0)
            return (char *)hit;
        n -= (size_t)(hit - h) + 1;
        h = hit + 1;
    }
    return NULL;
}

/* Last byte equal to c inside h[0..n), or NULL. */
static const char *mem_rfind(const char *h, size_t n, char c)
{
    while (n--)
        if (h[n] == c)
            return h + n;
    return NULL;
}

/* Non-overlapping occurrences of nd (m bytes) in h[0..n). */
static size_t mem_count(const char *h, size_t n, const char *nd, size_t m)
{
    size_t c = 0, at = 0;
    while (at <= n) {
        const char *hit = mem_find(h + at, n - at, nd, m);
        if (!hit)
            break;
        c++;
        at = (size_t)(hit - h) + m;
    }
    return c;
}

/* Length of the printable-ASCII run at s[0..n): the first byte outside
 * [0x20,0x7F] (a control byte, or any UTF-8 lead/continuation byte) ends it.
 * The read tool caps every line with it and both painter bulk-append paths
 * use it, so it is one function, vectorized.
 *
 * SSE2 has no unsigned byte compare, so the bounds go through saturating
 * subtracts: b >= 0x20 is (0x20 - b) == 0, b <= 0x7F is (b - 0x7F) == 0. */
static size_t ascii_run(const char *s, size_t n)
{
    size_t i = 0;
#if defined(_M_X64)
    const __m128i c20 = _mm_set1_epi8(0x20);
    const __m128i c7f = _mm_set1_epi8(0x7F);
    const __m128i zero = _mm_setzero_si128();
    while (i + 16 <= n) {
        __m128i v = _mm_loadu_si128((const __m128i *)(s + i));
        __m128i ge20 = _mm_cmpeq_epi8(_mm_subs_epu8(c20, v), zero);
        __m128i le7f = _mm_cmpeq_epi8(_mm_subs_epu8(v, c7f), zero);
        unsigned bad = ~((unsigned)_mm_movemask_epi8(_mm_and_si128(ge20,
                                                                   le7f)))
                       & 0xFFFFu;
        if (bad) {
            unsigned long bit;
            _BitScanForward(&bit, bad);
            return i + (size_t)bit;
        }
        i += 16;
    }
#endif
    while (i < n && (unsigned char)s[i] >= 0x20 && (unsigned char)s[i] < 0x80)
        i++;
    return i;
}

/* One vector pass over a freshly read buffer answers the three questions the
 * read path used to ask three ways: how many lines it holds (a page that stops
 * early still has to report the real length), whether every byte is ASCII
 * (pure ASCII is valid UTF-8 by construction, so a negative here lets the
 * caller skip MultiByteToWideChar's whole-file validation, which costs more
 * than reading the file did), and whether a control byte appears in the first
 * 8 KiB (the binary sniff).
 *
 * SSE2 has no unsigned byte compare, so `>= 0x80` is "negative when read
 * signed" and `< 0x20` is a signed compare with that case removed. The line
 * counter is 16 bytes wide and gains at most 4 per block, so it is drained
 * into the scalar total every 32 blocks (128 < 256). */
struct text_scan {
    size_t lines;   /* '\n' count, plus one if the buffer ends mid-line */
    int ascii;      /* every byte < 0x80 */
    int control;    /* a byte < 0x20 that is not \t \n \r in the head window */
};

#define TEXT_SNIFF_HEAD 8000

static struct text_scan scan_text(const char *s, size_t n)
{
    struct text_scan r = { 0, 1, 0 };
    size_t i = 0, nl = 0;
#if defined(_M_X64)
    const __m128i cnl = _mm_set1_epi8('\n');
    const __m128i c20 = _mm_set1_epi8(0x20);
    const __m128i ctab = _mm_set1_epi8('\t');
    const __m128i ccrlen = _mm_set1_epi8('\r');
    const __m128i zero = _mm_setzero_si128();
    __m128i acc = zero;
    unsigned blocks = 0, ctrl = 0;
    /* The head window first: the control-byte test costs six extra vector ops
     * per lane, and paying that over a whole file to answer a question about
     * its first 8 KiB is the difference between 0.03 and 0.10 ms on a
     * 660 KB read. */
    size_t head = n < TEXT_SNIFF_HEAD ? n : TEXT_SNIFF_HEAD;
    for (; i + 16 <= head; i += 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)(s + i));
        __m128i high = _mm_cmplt_epi8(v, zero);
        acc = _mm_sub_epi8(acc, _mm_cmpeq_epi8(v, cnl));
        __m128i lo = _mm_andnot_si128(high, _mm_cmplt_epi8(v, c20));
        __m128i ok = _mm_or_si128(_mm_cmpeq_epi8(v, ctab),
                                  _mm_or_si128(_mm_cmpeq_epi8(v, cnl),
                                               _mm_cmpeq_epi8(v, ccrlen)));
        ctrl |= (unsigned)_mm_movemask_epi8(_mm_andnot_si128(ok, lo));
        if (_mm_movemask_epi8(high))
            r.ascii = 0;
    }
    { /* drain: the body loop counts 64-byte blocks, not lanes */
        unsigned char l[16];
        _mm_storeu_si128((__m128i *)l, acc);
        for (int k = 0; k < 16; k++)
            nl += l[k];
        acc = zero;
    }
    for (; i < head; i++) {
        unsigned char c = (unsigned char)s[i];
        nl += c == '\n';
        if (c >= 0x80)
            r.ascii = 0;
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r')
            r.control = 1;
    }
    for (; i + 64 <= n; i += 64) {
        __m128i hi = zero;
        for (int k = 0; k < 4; k++) {
            __m128i v = _mm_loadu_si128((const __m128i *)(s + i + 16 * k));
            hi = _mm_or_si128(hi, _mm_cmplt_epi8(v, zero));
            acc = _mm_sub_epi8(acc, _mm_cmpeq_epi8(v, cnl));
        }
        if (_mm_movemask_epi8(hi))
            r.ascii = 0;
        if (++blocks == 32) { /* at most 4 per counter byte: 128 < 256 */
            unsigned char l[16];
            _mm_storeu_si128((__m128i *)l, acc);
            for (int k = 0; k < 16; k++)
                nl += l[k];
            acc = zero;
            blocks = 0;
        }
    }
    for (; i + 16 <= n; i += 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)(s + i));
        acc = _mm_sub_epi8(acc, _mm_cmpeq_epi8(v, cnl));
        if (_mm_movemask_epi8(_mm_cmplt_epi8(v, zero)))
            r.ascii = 0;
    }
    {
        unsigned char l[16];
        _mm_storeu_si128((__m128i *)l, acc);
        for (int k = 0; k < 16; k++)
            nl += l[k];
    }
    r.control |= ctrl != 0;
#endif
    for (; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        nl += c == '\n';
        if (c >= 0x80)
            r.ascii = 0;
    }
    r.lines = nl + (n && s[n - 1] != '\n' ? 1 : 0);
    return r;
}

/* --- dyn arrays ------------------------------------------------------- */

#define DA(T)      \
    struct {       \
        T *p;      \
        size_t n;  \
        size_t cap;\
    }

static void da_grow_(void **p, size_t *cap, size_t elem)
{
    *cap = *cap ? *cap * 2 : 8;
    *p = xrealloc(*p, *cap * elem);
}

#define DA_PUSH(da, v)                                   \
    do {                                                 \
        if ((da).n == (da).cap)                          \
            da_grow_((void **)&(da).p, &(da).cap, sizeof *(da).p); \
        (da).p[(da).n++] = (v);                          \
    } while (0)

#define DA_FREE(da) free((da).p)

/* --- bump arena (chunk list; allocations never move) ------------------ */

struct arena_chunk {
    struct arena_chunk *next;
    size_t cap;
    size_t used;
    /* chunk bytes follow the struct */
};

struct arena {
    struct arena_chunk *head;
    size_t default_chunk;
};

static void arena_init(struct arena *a, size_t chunk_size)
{
    a->head = NULL;
    a->default_chunk = chunk_size ? chunk_size : 64 * 1024;
}

static void arena_free(struct arena *a)
{
    struct arena_chunk *c = a->head;
    while (c) {
        struct arena_chunk *next = c->next;
        free(c);
        c = next;
    }
    a->head = NULL;
}

/* Drop every chunk (next allocation starts a fresh one). Used between SSE
 * events; anything that must survive was already copied out. The head chunk
 * is kept when it is default-sized so the per-event reset does not churn
 * malloc/free on the streaming path. */
static void arena_reset(struct arena *a)
{
    struct arena_chunk *c = a->head;
    if (!c)
        return;
    struct arena_chunk *next = c->next;
    c->next = NULL;
    a->head = c;
    while (next) {
        struct arena_chunk *dead = next;
        next = dead->next;
        free(dead);
    }
    if (c->cap <= a->default_chunk)
        c->used = 0;
    else {
        free(c);
        a->head = NULL;
    }
}

static void *arena_alloc(struct arena *a, size_t n)
{
    n = (n + 15u) & ~(size_t)15u;
    struct arena_chunk *c = a->head;
    if (!c || c->cap - c->used < n) {
        size_t cap = a->default_chunk;
        if (cap < n)
            cap = n;
        c = xmalloc(sizeof *c + cap);
        c->next = a->head;
        c->cap = cap;
        c->used = 0;
        a->head = c;
    }
    void *p = (char *)(c + 1) + c->used;
    c->used += n;
    return p;
}

/* ==========================================================================
 * 2. json — arena-backed parser, zero-copy strings
 * ========================================================================== */

enum jtag {
    J_NULL,
    J_FALSE,
    J_TRUE,
    J_NUM,
    J_STR,
    J_ARR,
    J_OBJ,
};

struct jnode {
    uint8_t tag;
    double num;         /* J_NUM */
    int64_t inum;       /* J_NUM: value when the literal was an integer */
    struct str raw;     /* J_STR: escaped slice into the source buffer;
                         * J_OBJ pair: the key */
    struct jnode *val;  /* J_OBJ pair: value node */
    struct jnode *head; /* J_OBJ: first pair; J_ARR: first item */
    struct jnode *next; /* sibling in a pair/item chain */
};

struct json_parser {
    const char *s;
    size_t n;
    size_t i;
    struct arena *arena;
    int depth;
};

#define JSON_MAX_DEPTH 64

/* Skip JSON whitespace from index i. The parser and the protocol fast scan
 * share this one reader: two copies of the whitespace rule is two places for
 * them to disagree. */
static size_t jw(const char *s, size_t n, size_t i)
{
    while (i < n) {
        char c = s[i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            break;
        i++;
    }
    return i;
}

static struct jnode *jnew(struct json_parser *p, uint8_t tag)
{
    struct jnode *node = arena_alloc(p->arena, sizeof *node);
    memset(node, 0, sizeof *node);
    node->tag = tag;
    return node;
}

static int jhex(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* s[i] is the backslash of an escape: validate it and return the index just
 * past the sequence, or (size_t)-1 on malformed input. One rule for every
 * scanner, so what the parser accepts and what the fast scan accepts match. */
static size_t jstr_escape(const char *s, size_t n, size_t i)
{
    if (++i >= n)
        return (size_t)-1;
    char e = s[i];
    if (e == 'u') {
        for (int k = 1; k <= 4; k++)
            if (i + (size_t)k >= n || jhex(s[i + (size_t)k]) < 0)
                return (size_t)-1;
        return i + 5;
    }
    if (e == '"' || e == '\\' || e == '/' || e == 'b' || e == 'f' || e == 'n'
        || e == 'r' || e == 't')
        return i + 1;
    return (size_t)-1;
}

/* The end of a JSON string whose content starts at s[i]: the slice between the
 * quotes (when out is given) and the index past the closing quote, or
 * (size_t)-1.
 *
 * The first 24 bytes are the probe: envelope keys plus short values ("stop",
 * ids, small argument fragments) end inside it, and an SSE2 block decides 16
 * of those bytes at once — the vector compare is the whole price at these
 * lengths, and the load stays inside the buffer. Longer strings (model
 * content, tool arguments) fall through to memchr windows. Both scans stay
 * inside one window, so an escape never re-scans from the quote (that is
 * quadratic in the escape count). */
#define JSTR_WINDOW 1024
#define JSTR_PROBE 24

/* First '"' or '\\' inside s[0..probe): the index, or probe when neither
 * occurs. One SSE2 block covers 16 of the probe's 24 bytes — envelope keys
 * ("choices", "reasoning_content") and short values ("stop", ids) end
 * inside it, and the vector compare replaces 16 pairs of scalar compares.
 * The load stays inside [s, s+n) because k+16 <= probe <= n-i. */
static size_t jstr_probe_hit(const char *s, size_t i, size_t probe)
{
    size_t k = 0;
#if defined(_M_X64)
    const __m128i vq = _mm_set1_epi8('"');
    const __m128i vb = _mm_set1_epi8('\\');
    while (k + 16 <= probe) {
        __m128i v = _mm_loadu_si128((const __m128i *)(s + i + k));
        unsigned m = (unsigned)_mm_movemask_epi8(
            _mm_or_si128(_mm_cmpeq_epi8(v, vq), _mm_cmpeq_epi8(v, vb)));
        if (m) {
            unsigned long bit;
            _BitScanForward(&bit, m);
            return k + (size_t)bit;
        }
        k += 16;
    }
#endif
    while (k < probe) {
        unsigned char c = (unsigned char)s[i + k];
        if (c == '"' || c == '\\')
            return k;
        k++;
    }
    return probe;
}

static size_t jstr_end(const char *s, size_t n, size_t i, struct str *out)
{
    size_t start = i;
    while (i < n) {
        size_t probe = n - i < JSTR_PROBE ? n - i : JSTR_PROBE;
        size_t k = jstr_probe_hit(s, i, probe);
        if (k < probe) {
            if (s[i + k] == '"') {
                if (out) {
                    out->p = s + start;
                    out->n = i + k - start;
                }
                return i + k + 1;
            }
            i = jstr_escape(s, n, i + k);
            if (i == (size_t)-1)
                return (size_t)-1;
            continue; /* resume the probe after the escape */
        }
        if (probe < JSTR_PROBE)
            return (size_t)-1; /* buffer exhausted: unterminated */
        i += JSTR_PROBE;

        /* window phase: ONE pass finds either delimiter, so an escape-free
         * string (the norm) does not pay the same range twice. */
        size_t rest = n - i;
        size_t win = rest > JSTR_WINDOW ? JSTR_WINDOW : rest;
        size_t k2 = jstr_probe_hit(s, i, win);
        if (k2 < win) {
            if (s[i + k2] == '"') {
                if (out) {
                    out->p = s + start;
                    out->n = i + k2 - start;
                }
                return i + k2 + 1;
            }
            i = jstr_escape(s, n, i + k2);
            if (i == (size_t)-1)
                return (size_t)-1;
            continue;
        }
        i += win; /* nothing interesting in this window */
    }
    return (size_t)-1;
}

/* Parse a string literal starting at the opening quote. Returns the raw
 * escaped slice (between the quotes) and advances past the closing quote,
 * or -1 on error. */
static int jparse_string_raw(struct json_parser *p, struct str *out)
{
    if (p->i >= p->n || p->s[p->i] != '"')
        return -1;
    size_t after = jstr_end(p->s, p->n, p->i + 1, out);
    if (after == (size_t)-1)
        return -1;
    p->i = after;
    return 0;
}

static int jhex_quad(const char *s, size_t n, size_t *i)
{
    if (*i + 4 > n)
        return -1;
    int v = 0;
    for (int k = 0; k < 4; k++) {
        int h = jhex(s[*i + (size_t)k]);
        if (h < 0)
            return -1;
        v = v * 16 + h;
    }
    *i += 4;
    return v;
}

/* Decode one \uXXXX escape at s[*i] (after the 'u') into cp, advancing *i.
 * Handles surrogate pairs; returns -1 on bad input. */
static int jdecode_u(const char *s, size_t n, size_t *i, uint32_t *cp)
{
    int v = jhex_quad(s, n, i);
    if (v < 0)
        return -1;
    if (v >= 0xD800 && v <= 0xDBFF) {
        /* high surrogate: expect \uXXXX low surrogate next */
        if (*i + 2 > n || s[*i] != '\\' || s[*i + 1] != 'u') {
            v = 0xFFFD;
        } else {
            *i += 2;
            int lo = jhex_quad(s, n, i);
            if (lo < 0)
                return -1;
            if (lo < 0xDC00 || lo > 0xDFFF)
                return -1;
            v = 0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00);
        }
    } else if (v >= 0xDC00 && v <= 0xDFFF) {
        v = 0xFFFD;
    }
    *cp = (uint32_t)v;
    return 0;
}

/* First '\\' in s[0..n), or NULL. SSE deltas are a handful of bytes, where
 * the memchr call overhead is the whole cost: short strings scan by hand,
 * long ones (file contents, tool arguments) get the vectorized scan. */
static const char *find_backslash(const char *s, size_t n)
{
    if (n > 32)
        return (const char *)memchr(s, '\\', n);
    for (size_t k = 0; k < n; k++)
        if (s[k] == '\\')
            return s + k;
    return NULL;
}

/* Decode a raw string slice (with escapes) into buf as UTF-8. Escape-free
 * runs are copied in bulk — model deltas are almost never escaped. */
static void jdecode_str(struct str raw, struct buf *out)
{
    size_t i = 0;
    while (i < raw.n) {
        const char *bs = find_backslash(raw.p + i, raw.n - i);
        if (!bs) {
            buf_append_n(out, raw.p + i, raw.n - i);
            break;
        }
        size_t run = (size_t)(bs - (raw.p + i));
        if (run)
            buf_append_n(out, raw.p + i, run);
        i += run + 1; /* skip the backslash */
        if (i >= raw.n)
            break;
        char e = raw.p[i++];
        switch (e) {
        case '"': buf_appendc(out, '"'); break;
        case '\\': buf_appendc(out, '\\'); break;
        case '/': buf_appendc(out, '/'); break;
        case 'b': buf_appendc(out, '\b'); break;
        case 'f': buf_appendc(out, '\f'); break;
        case 'n': buf_appendc(out, '\n'); break;
        case 'r': buf_appendc(out, '\r'); break;
        case 't': buf_appendc(out, '\t'); break;
        case 'u': {
            uint32_t cp;
            if (jdecode_u(raw.p, raw.n, &i, &cp) == 0)
                buf_append_cp(out, cp);
            break;
        }
        default: break;
        }
    }
}

static struct jnode *jparse_value(struct json_parser *p);

/* Span of a JSON number literal at s[i]; *is_int is clear when it carried a
 * fraction or exponent. The end index equals the start when s[i] does not
 * begin a number. Lenient on purpose (RFC-invalid "-", "1.", "1e" read as
 * 0/1): model output beats strictness here, and both readers share this. */
static size_t num_span(const char *s, size_t n, size_t i, int *is_int)
{
    if (i < n && s[i] == '-')
        i++;
    while (i < n && s[i] >= '0' && s[i] <= '9')
        i++;
    *is_int = 1;
    if (i < n && s[i] == '.') {
        *is_int = 0;
        i++;
        while (i < n && s[i] >= '0' && s[i] <= '9')
            i++;
    }
    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        *is_int = 0;
        i++;
        if (i < n && (s[i] == '+' || s[i] == '-'))
            i++;
        while (i < n && s[i] >= '0' && s[i] <= '9')
            i++;
    }
    return i;
}

/* Convert a number literal shorter than 40 bytes exactly the way both readers
 * do: integers through _strtoui64, anything else through strtod and a cast,
 * anything 40 bytes or longer reading as 0. */
static double num_convert(const char *s, size_t len, int is_int, int64_t *inum)
{
    *inum = 0;
    if (len >= 40)
        return 0;
    char tmp[40];
    memcpy(tmp, s, len);
    tmp[len] = '\0';
    double d = strtod(tmp, NULL);
    *inum = is_int ? (int64_t)_strtoui64(tmp, NULL, 10) : (int64_t)d;
    return d;
}

static struct jnode *jparse_number(struct json_parser *p)
{
    int is_int;
    size_t start = p->i;
    p->i = num_span(p->s, p->n, p->i, &is_int);
    if (p->i == start)
        return NULL;
    struct jnode *node = jnew(p, J_NUM);
    node->num = num_convert(p->s + start, p->i - start, is_int, &node->inum);
    return node;
}

static struct jnode *jparse_object(struct json_parser *p)
{
    p->i++; /* { */
    struct jnode *obj = jnew(p, J_OBJ);
    struct jnode **tail = &obj->head;
    p->i = jw(p->s, p->n, p->i);
    if (p->i < p->n && p->s[p->i] == '}') {
        p->i++;
        return obj;
    }
    for (;;) {
        p->i = jw(p->s, p->n, p->i);
        struct str key;
        if (jparse_string_raw(p, &key) != 0)
            return NULL;
        p->i = jw(p->s, p->n, p->i);
        if (p->i >= p->n || p->s[p->i] != ':')
            return NULL;
        p->i++;
        struct jnode *val = jparse_value(p);
        if (!val)
            return NULL;
        struct jnode *pair = jnew(p, J_STR);
        pair->raw = key;
        pair->val = val;
        *tail = pair;
        tail = &pair->next;
        p->i = jw(p->s, p->n, p->i);
        if (p->i < p->n && p->s[p->i] == ',') {
            p->i++;
            continue;
        }
        if (p->i < p->n && p->s[p->i] == '}') {
            p->i++;
            return obj;
        }
        return NULL;
    }
}

static struct jnode *jparse_array(struct json_parser *p)
{
    p->i++; /* [ */
    struct jnode *arr = jnew(p, J_ARR);
    struct jnode **tail = &arr->head;
    p->i = jw(p->s, p->n, p->i);
    if (p->i < p->n && p->s[p->i] == ']') {
        p->i++;
        return arr;
    }
    for (;;) {
        struct jnode *val = jparse_value(p);
        if (!val)
            return NULL;
        *tail = val;
        tail = &val->next;
        p->i = jw(p->s, p->n, p->i);
        if (p->i < p->n && p->s[p->i] == ',') {
            p->i++;
            continue;
        }
        if (p->i < p->n && p->s[p->i] == ']') {
            p->i++;
            return arr;
        }
        return NULL;
    }
}

static struct jnode *jparse_value(struct json_parser *p)
{
    if (++p->depth > JSON_MAX_DEPTH)
        return NULL;
    struct jnode *result = NULL;
    p->i = jw(p->s, p->n, p->i);
    if (p->i >= p->n)
        goto out;
    char c = p->s[p->i];
    if (c == '"') {
        struct str raw;
        if (jparse_string_raw(p, &raw) != 0)
            goto out;
        result = jnew(p, J_STR);
        result->raw = raw;
    } else if (c == '{') {
        result = jparse_object(p);
    } else if (c == '[') {
        result = jparse_array(p);
    } else if (c == 't' && p->i + 4 <= p->n && memcmp(p->s + p->i, "true", 4) == 0) {
        p->i += 4;
        result = jnew(p, J_TRUE);
    } else if (c == 'f' && p->i + 5 <= p->n && memcmp(p->s + p->i, "false", 5) == 0) {
        p->i += 5;
        result = jnew(p, J_FALSE);
    } else if (c == 'n' && p->i + 4 <= p->n && memcmp(p->s + p->i, "null", 4) == 0) {
        p->i += 4;
        result = jnew(p, J_NULL);
    } else {
        result = jparse_number(p);
    }
out:
    p->depth--;
    return result;
}

/* Parse one JSON document. Returns NULL on error; trailing garbage is
 * ignored (SSE chunks may pad). */
static struct jnode *json_parse(struct arena *arena, const char *s, size_t n)
{
    struct json_parser p = { s, n, 0, arena, 0 };
    struct jnode *v = jparse_value(&p);
    return v;
}

/* --- accessors -------------------------------------------------------- */

static struct jnode *jobj_get(const struct jnode *obj, const char *key)
{
    if (!obj || obj->tag != J_OBJ)
        return NULL;
    for (struct jnode *pair = obj->head; pair; pair = pair->next) {
        if (str_eqc(pair->raw, key))
            return pair->val;
    }
    return NULL;
}

static int64_t jnum_i(const struct jnode *node)
{
    return node ? node->inum : 0;
}

/* A decoded, NUL-terminated copy of a raw (still escaped) JSON string slice.
 * Distinct from str_dupz(), which copies a slice verbatim. */
static char *jdecode_dupz(struct str raw)
{
    struct buf b = BUF_INIT;
    jdecode_str(raw, &b);
    return buf_detach(&b);
}

static char *jstr_dupz(const struct jnode *node)
{
    if (!node || node->tag != J_STR)
        return NULL;
    return jdecode_dupz(node->raw);
}

/* Decoded string, or a copy of fallback when the node is missing. */
static char *jstr_or(const struct jnode *node, const char *fallback)
{
    return xstr_or(jstr_dupz(node), fallback);
}

/* --- serialization helpers -------------------------------------------- */

/* json_escape_append copies in bulk and only walks byte by byte across a span
 * that actually needs escaping. Session logs and request serialization push
 * megabytes of mostly plain UTF-8 through it every round, so the clean-run
 * skip decides the cost: SSE2 clears sixteen bytes per compare.
 *
 * SSE2 has no unsigned byte compare. `c < 0x20` unsigned is
 * `0x20 > c` AND `c >= 0x80` false — i.e. the signed compare against 0x20 with
 * the high-bit bytes masked back out, because those signed "less than 0x20"
 * while unsigned they are ordinary text. The two equality tests are exact. */
static void json_escape_append(struct buf *b, const char *s, size_t n)
{
    buf_reserve(b, n + 16);
    size_t start = 0, i = 0;
    while (i < n) {
#if defined(_M_X64)
        const __m128i c20 = _mm_set1_epi8(0x20);
        const __m128i cq = _mm_set1_epi8('"');
        const __m128i cbs = _mm_set1_epi8('\\');
        const __m128i zero = _mm_setzero_si128();
        while (i + 16 <= n) {
            __m128i v = _mm_loadu_si128((const __m128i *)(s + i));
            __m128i high = _mm_cmpgt_epi8(zero, v);
            __m128i low = _mm_andnot_si128(high, _mm_cmplt_epi8(v, c20));
            unsigned m = (unsigned)_mm_movemask_epi8(
                _mm_or_si128(low, _mm_or_si128(_mm_cmpeq_epi8(v, cq),
                                               _mm_cmpeq_epi8(v, cbs))));
            if (m) {
                unsigned long bit;
                _BitScanForward(&bit, m);
                i += (size_t)bit;
                break;
            }
            i += 16;
        }
#endif
        while (i < n) {
            unsigned char c = (unsigned char)s[i];
            char ubuf[8];
            const char *esc;
            size_t esclen;
            switch (c) {
            case '"': esc = "\\\""; esclen = 2; break;
            case '\\': esc = "\\\\"; esclen = 2; break;
            case '\b': esc = "\\b"; esclen = 2; break;
            case '\f': esc = "\\f"; esclen = 2; break;
            case '\n': esc = "\\n"; esclen = 2; break;
            case '\r': esc = "\\r"; esclen = 2; break;
            case '\t': esc = "\\t"; esclen = 2; break;
            default:
                if (c >= 0x20) {
                    i++; /* plain byte: ASCII or UTF-8 lead/continuation */
                    continue;
                }
                esclen = (size_t)snprintf(ubuf, sizeof ubuf, "\\u%04x", c);
                esc = ubuf;
                break;
            }
            buf_append_n(b, s + start, i - start);
            buf_append_n(b, esc, esclen);
            start = ++i;
            break; /* one escape emitted: retry the vector skip */
        }
        if (i >= n)
            break;
    }
    buf_append_n(b, s + start, n - start);
}

/* ==========================================================================
 * 3. utf8 — decode / encode / display width
 * ========================================================================== */

/* Decode one codepoint at s[0..n); returns bytes consumed (>=1), or 0 when
 * invalid; *cp gets the codepoint (U+FFFD on invalid). */
static size_t u8_decode(const char *s, size_t n, uint32_t *cp)
{
    if (!n)
        return 0;
    unsigned char b0 = (unsigned char)s[0];
    if (b0 < 0x80) {
        *cp = b0;
        return 1;
    }
    uint32_t v;
    size_t len;
    if ((b0 & 0xE0) == 0xC0) {
        v = b0 & 0x1F;
        len = 2;
    } else if ((b0 & 0xF0) == 0xE0) {
        v = b0 & 0x0F;
        len = 3;
    } else if ((b0 & 0xF8) == 0xF0) {
        v = b0 & 0x07;
        len = 4;
    } else {
        goto invalid;
    }
    if (n < len)
        goto invalid;
    for (size_t k = 1; k < len; k++) {
        unsigned char b = (unsigned char)s[k];
        if ((b & 0xC0) != 0x80)
            goto invalid;
        v = (v << 6) | (b & 0x3F);
    }
    if ((len == 2 && v < 0x80) || (len == 3 && (v < 0x800
             || (v >= 0xD800 && v <= 0xDFFF)))
        || (len == 4 && v < 0x10000) || v > 0x10FFFF)
        goto invalid;
    *cp = v;
    return len;
invalid:
    *cp = 0xFFFD;
    return 0;
}

/* The shape every UTF-8 walk in this file wants: the codepoint and its byte
 * length, with the length forced to at least 1 so a malformed byte still
 * advances the walk instead of spinning on it. */
static size_t u8_step(const char *s, size_t n, uint32_t *cp)
{
    size_t len = u8_decode(s, n, cp);
    return len ? len : 1;
}

/* Same, for the walks that only split: the caret paints a whole glyph and
 * never asks what it is. */
static size_t u8_len(const char *s, size_t n)
{
    uint32_t cp;
    return u8_step(s, n, &cp);
}

/* Encode cp as UTF-8 into tmp (at least 4 bytes); returns bytes used. */
static size_t u8_encode(uint32_t cp, char *tmp)
{
    if (cp < 0x80) {
        tmp[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        tmp[0] = (char)(0xC0 | (cp >> 6));
        tmp[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        tmp[0] = (char)(0xE0 | (cp >> 12));
        tmp[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    tmp[0] = (char)(0xF0 | (cp >> 18));
    tmp[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    tmp[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    tmp[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/* Inclusive codepoint ranges rendered two columns wide: CJK, Hangul, Kana,
 * fullwidth forms, the common emoji planes and the East Asian Ambiguous
 * blocks (ambiguous matters — under-counting them makes rows overflow and
 * the cursor desync). MUST stay sorted by lo: u8_cp_width binary-searches
 * it. 0x2500-0x25FF (box drawing) stays narrow: Windows Terminal renders
 * these 1 cell, and kk's own decorations use them. */
static const struct {
    uint32_t lo, hi;
} WIDE_RANGES[] = {
    { 0x1100, 0x115F }, /* Hangul Jamo */
    { 0x2010, 0x2027 }, /* hyphens, bullet, ellipsis, em dash */
    { 0x2030, 0x205E }, /* per-mille, reference marks */
    { 0x2190, 0x21FF }, /* arrows */
    { 0x2200, 0x22FF }, /* math operators */
    { 0x2300, 0x23FF }, /* misc technical (covers 0x2329..0x232A) */
    { 0x2460, 0x24FF }, /* enclosed alphanumerics */
    { 0x2600, 0x26FF }, /* misc symbols */
    { 0x2700, 0x27BF }, /* dingbats */
    /* 0x2500-0x25FF (box drawing, blocks) stays narrow: Windows Terminal
     * renders these 1 cell, and kk's own decorations use them */
    { 0x2B00, 0x2BFF }, /* misc symbols and arrows */
    { 0x2E80, 0x303E }, /* CJK radicals .. CJK symbols */
    { 0x3041, 0x33FF }, /* Hiragana .. CJK compatibility */
    { 0x3400, 0x4DBF }, /* CJK ext A */
    { 0x4E00, 0x9FFF }, /* CJK unified */
    { 0xA000, 0xA4CF }, /* Yi */
    { 0xA960, 0xA97F },
    { 0xAC00, 0xD7A3 }, /* Hangul syllables */
    { 0xF900, 0xFAFF }, /* CJK compatibility ideographs */
    { 0xFE10, 0xFE19 },
    { 0xFE30, 0xFE6F },
    { 0xFF00, 0xFF60 }, /* fullwidth forms */
    { 0xFFE0, 0xFFE6 },
    { 0x16FE0, 0x16FE4 },
    { 0x17000, 0x187F7 },
    { 0x18800, 0x18CD5 },
    { 0x1B000, 0x1B2FB },
    { 0x1F004, 0x1F004 },
    { 0x1F0CF, 0x1F0CF },
    { 0x1F18E, 0x1F18E },
    { 0x1F191, 0x1F19A },
    { 0x1F200, 0x1F320 }, /* enclosed ideographs .. emoji */
    { 0x1F32D, 0x1F335 },
    { 0x1F337, 0x1F37C },
    { 0x1F37E, 0x1F393 },
    { 0x1F3A0, 0x1F3CA },
    { 0x1F3CF, 0x1F3D3 },
    { 0x1F3E0, 0x1F3F0 },
    { 0x1F3F4, 0x1F3F4 },
    { 0x1F3F8, 0x1F43E },
    { 0x1F440, 0x1F440 },
    { 0x1F442, 0x1F4FC },
    { 0x1F4FF, 0x1F53D },
    { 0x1F54B, 0x1F54E },
    { 0x1F550, 0x1F567 },
    { 0x1F57A, 0x1F57A },
    { 0x1F595, 0x1F596 },
    { 0x1F5A4, 0x1F5A4 },
    { 0x1F5FB, 0x1F64F },
    { 0x1F680, 0x1F6C5 },
    { 0x1F6CC, 0x1F6CC },
    { 0x1F6D0, 0x1F6D2 },
    { 0x1F6EB, 0x1F6EC },
    { 0x1F6F4, 0x1F6FC },
    { 0x1F7E0, 0x1F7EB },
    { 0x1F90C, 0x1F9FF }, /* supplemental symbols */
    { 0x1FA70, 0x1FAFF },
    { 0x20000, 0x2FFFD }, /* CJK ext B.. */
    { 0x30000, 0x3FFFD },
};

static int u8_cp_width(uint32_t cp)
{
    if (cp == 0)
        return 0;
    if (cp < 0x300)
        return 1; /* ASCII + Latin: the hot path */
    if (cp <= 0x36F)
        return 0; /* combining marks */
    if ((cp >= 0x200B && cp <= 0x200F) || (cp >= 0xFE00 && cp <= 0xFE0F))
        return 0; /* zero-width chars and variation selectors */
    if (cp >= 0x4E00 && cp <= 0x9FFF)
        return 2; /* CJK unified: the dominant wide range */
    if (cp < 0x1100)
        return 1;
    size_t lo = 0, hi = sizeof WIDE_RANGES / sizeof WIDE_RANGES[0];
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cp < WIDE_RANGES[mid].lo)
            hi = mid;
        else if (cp > WIDE_RANGES[mid].hi)
            lo = mid + 1;
        else
            return 2;
    }
    return 1;
}

/* Index of the codepoint start at or before byte i (for cursor movement). */
static size_t u8_prev(const char *s, size_t i)
{
    if (i == 0)
        return 0;
    size_t j = i - 1;
    while (j > 0 && ((unsigned char)s[j] & 0xC0) == 0x80)
        j--;
    return j;
}

/* The largest cut position <= i that does not split a codepoint: a byte at the
 * cut that is a continuation means its sequence started earlier. This is
 * u8_prev(s, i + 1) — the byte at i is examined instead of the one before it —
 * and every display cap that must not print half a glyph goes through one
 * definition of the boundary. */
static size_t u8_floor(const char *s, size_t i)
{
    return u8_prev(s, i + 1);
}

static size_t u8_next(const char *s, size_t n, size_t i)
{
    if (i >= n)
        return n;
    size_t j = i + 1;
    while (j < n && ((unsigned char)s[j] & 0xC0) == 0x80)
        j++;
    return j;
}

/* Display width of the first n bytes of s, skipping ANSI SGR sequences.
 * Used for painter prefixes and prompt strings that embed style codes. */
static size_t visible_width(const char *s, size_t n)
{
    size_t w = 0, i = 0;
    while (i < n) {
        if ((unsigned char)s[i] == 0x1B) {
            i += 2; /* ESC [ */
            while (i < n && (unsigned char)s[i] != 'm')
                i++;
            i++;
            continue;
        }
        unsigned char b = (unsigned char)s[i];
        if (b != 0 && b < 0x80) {
            w++; /* ASCII: width 1, no decode round-trip */
            i++;
            continue;
        }
        uint32_t cp;
        size_t clen = u8_step(s + i, n - i, &cp);
        w += (size_t)u8_cp_width(cp);
        i += clen;
    }
    return w;
}

/* Make a byte buffer valid UTF-8: when it isn't, transcode from the console
 * output codepage (native tools emit GBK on zh-CN machines). */
static void transcode_to_utf8(char **pdata, size_t *plen)
{
    char *data = *pdata;
    size_t len = *plen;
    if (!len || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data,
                                    (int)len, NULL, 0) != 0)
        return;
    UINT cp = GetConsoleOutputCP();
    if (!cp)
        cp = CP_OEMCP;
    int wn = MultiByteToWideChar(cp, 0, data, (int)len, NULL, 0);
    if (wn <= 0)
        return;
    wchar_t *w = xmalloc((size_t)wn * sizeof(wchar_t));
    MultiByteToWideChar(cp, 0, data, (int)len, w, wn);
    int un = WideCharToMultiByte(CP_UTF8, 0, w, wn, NULL, 0, NULL, NULL);
    if (un > 0) {
        char *u = xmalloc((size_t)un + 1);
        WideCharToMultiByte(CP_UTF8, 0, w, wn, u, un, NULL, NULL);
        u[un] = '\0'; /* every caller walks/strlens the result: the
                       * terminator was never written (ASan caught the
                       * overruns in read/write/bash paths) */
        free(data);
        *pdata = u;
        *plen = (size_t)un;
    }
    free(w);
}

/* ==========================================================================
 * 4. terminal — console setup, output lock, control handler
 * ========================================================================== */

static HANDLE g_hstdin;
static HANDLE g_hstdout;
static int g_console_out; /* stdout is a real console: write via WriteConsoleA */
static int g_emit_vt;     /* SGR styling allowed (verified VT, or forced) */
static int g_console_in;  /* stdin is a real console */
static int g_term_cols = 100;
static int g_term_rows = 30;

/* Set from the Ctrl handler; polled by transport and tool loops. */
static volatile LONG g_cancel;

/* Performance-counter frequency, read once in term_init: GetTickCount's
 * 15.6 ms clock floor would turn the painter's 20 ms frame throttle into a
 * 31 ms one. */
static LARGE_INTEGER g_qpc_freq;

static DWORD now_ms(void)
{
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (DWORD)(c.QuadPart * 1000 / (g_qpc_freq.QuadPart
                                            ? g_qpc_freq.QuadPart
                                            : 1));
}

static BOOL WINAPI kk_ctrl_handler(DWORD type)
{
    (void)type;
    /* first Ctrl+C cancels the stream; a second one while the cancel is
     * still pending kills the process for real */
    if (InterlockedExchange(&g_cancel, 1))
        ExitProcess(130);
    return TRUE;
}

static void term_size_refresh(void)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!g_console_out)
        return;
    if (GetConsoleScreenBufferInfo(g_hstdout, &csbi)) {
        g_term_cols = (int)(csbi.srWindow.Right - csbi.srWindow.Left) + 1;
        g_term_rows = (int)(csbi.srWindow.Bottom - csbi.srWindow.Top) + 1;
        if (g_term_cols < 20)
            g_term_cols = 20;
        if (g_term_cols > 500)
            g_term_cols = 500;
    }
}

static void term_init(void)
{
    g_hstdin = GetStdHandle(STD_INPUT_HANDLE);
    g_hstdout = GetStdHandle(STD_OUTPUT_HANDLE);

    DWORD mode;
    g_console_out = GetConsoleMode(g_hstdout, &mode) != 0;
    g_console_in = g_hstdin != INVALID_HANDLE_VALUE
        && GetConsoleMode(g_hstdin, &mode) != 0;

    if (g_console_out) {
        GetConsoleMode(g_hstdout, &mode);
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
        /* verify the flag stuck: on consoles without VT support we degrade
         * to plain text instead of spraying escape sequences */
        g_emit_vt = SetConsoleMode(g_hstdout, mode) != 0;
        SetConsoleOutputCP(CP_UTF8);
        term_size_refresh();
    }

    /* test affordance: emit VT styling even when stdout is redirected */
    {
        char *fc = env_get("KK_FORCE_CONSOLE");
        if (fc) {
            g_emit_vt = 1;
            free(fc);
        }
    }

    if (g_console_in)
        SetConsoleCP(CP_UTF8);

    QueryPerformanceFrequency(&g_qpc_freq);
    SetConsoleCtrlHandler(kk_ctrl_handler, TRUE);
}

/* --- raw VT byte input --------------------------------------------------- */

/* Input is read as the terminal's raw VT byte stream (ReadFile +
 * ENABLE_VIRTUAL_TERMINAL_INPUT), never as INPUT_RECORDs: conhost's key
 * translator mangles bracketed-paste markers and Alt chords. Two consumers
 * share the byte layer — the composer (edit_line, which also reads during a
 * turn) and the session picker — each bracketed by term_raw_begin/term_raw_end,
 * never overlapping.
 */
#define VT_INPUT_FLAG 0x0200 /* ENABLE_VIRTUAL_TERMINAL_INPUT */

static BOOL term_raw_begin(DWORD *saved)
{
    DWORD mode;
    if (!g_console_in || !GetConsoleMode(g_hstdin, &mode))
        return FALSE;
    *saved = mode;
    mode |= ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT | VT_INPUT_FLAG;
    mode &= ~(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
    return SetConsoleMode(g_hstdin, mode);
}

static void term_raw_end(DWORD saved)
{
    SetConsoleMode(g_hstdin, saved);
}

/* One shared read buffer (the consumers never overlap): pastes arrive in
 * multi-KB bursts and 1-byte ReadFile calls made pasting visibly slow. */
static unsigned char term_in[4096];
static size_t term_in_len, term_in_pos;

/* Console handles signal when an input record is queued; bounded wait gives
 * the escape parser its inter-byte timeout. Bytes already pulled into term_in
 * count as readable: blocking while a multi-byte chunk sits buffered meters
 * input out one keystroke at a time. */
static BOOL term_wait_readable(int timeout_ms)
{
    if (term_in_pos < term_in_len)
        return TRUE;
    return WaitForSingleObject(g_hstdin, (DWORD)timeout_ms) == WAIT_OBJECT_0;
}

/* One byte from the buffer: 1 = byte, 0 = Ctrl+Z EOF mark, -1 = closed. */
static int term_read_byte(unsigned char *b)
{
    if (term_in_pos < term_in_len) {
        *b = term_in[term_in_pos++];
        return 1;
    }
    DWORD got = 0;
    if (!ReadFile(g_hstdin, term_in, sizeof term_in, &got, NULL))
        return -1; /* handle closed: real end of input */
    if (got == 0)
        return 0; /* conhost's Ctrl+Z mark surfaced as an empty read */
    term_in_len = got;
    term_in_pos = 1;
    *b = term_in[0];
    return 1;
}

static int term_read_byte_timeout(unsigned char *b, int timeout_ms)
{
    /* 1 = byte; 0 = timeout or a Ctrl+Z EOF mark (treated the same by
     * sequence collectors: the pending wait simply ends); -1 = closed */
    if (term_in_pos < term_in_len) {
        *b = term_in[term_in_pos++];
        return 1;
    }
    if (!term_wait_readable(timeout_ms))
        return 0;
    return term_read_byte(b);
}

/* Read a CSI/SS3 sequence after ESC [ / ESC O: parameter bytes 0x20..0x3F
 * (up to cap of them), then one final byte 0x40..0x7E. Returns the final
 * byte, 0 on timeout. cap = 0 turns this into a pure drain. */
static unsigned char csi_read(char *params, size_t cap, size_t *np)
{
    *np = 0;
    for (;;) {
        unsigned char c;
        if (term_read_byte_timeout(&c, 50) <= 0)
            return 0;
        if (c >= 0x40 && c <= 0x7E)
            return c;
        if (c >= 0x20 && c <= 0x3F && *np < cap)
            params[(*np)++] = (char)c;
    }
}

/* All terminal/pipe output funnels through here. UTF-8 in, bytes out;
 * console writes go through WriteConsoleA (honors the VT state and the
 * UTF-8 output codepage), redirect writes through WriteFile. The lock keeps
 * the wait-spinner thread from interleaving with stream paint. */
static SRWLOCK g_out_lock = SRWLOCK_INIT;
static volatile LONG g_busy;    /* 0 idle, 1 waiting, 2 generating */
static int g_dock;              /* REPL dock active: pin composer during turns */
/* Shared with the spinner thread: g_status_model is only written while no
 * turn runs, and g_ctx_tokens updates are x64-aligned 64-bit stores the
 * spinner may read a frame stale — both benign by construction. */
static char *g_status_model; /* own copy: the model name for the status row */
static int64_t g_ctx_tokens; /* last API-reported prompt tokens (0=unknown) */

static void out_write_unlocked(const char *s, size_t n)
{
    if (!n)
        return;
    if (g_console_out) {
        /* WriteConsoleA takes DWORD-length runs; chunk huge writes */
        while (n > 0) {
            DWORD chunk = n > 0x10000 ? 0x10000 : (DWORD)n;
            DWORD wrote = 0;
            if (!WriteConsoleA(g_hstdout, s, chunk, &wrote, NULL))
                return;
            s += wrote;
            n -= wrote;
            if (wrote == 0)
                return;
        }
    } else {
        DWORD wrote = 0;
        WriteFile(g_hstdout, s, (DWORD)n, &wrote, NULL);
    }
}

/* Content-end tracking: EVERY transcript write (any thread) seeks to the
 * tracked end and re-tracks after, so the stream always appends after the
 * last byte no matter where the composer parked the cursor. Panel paints
 * (composer frame, status row, menu, region setup) go through the
 * out_frame_* variants which write without seeking. All under g_out_lock. */
static SHORT g_content_x, g_content_y; /* buffer coords, -1 = unset */
static int g_no_seek; /* full-screen overlays (session picker) write raw */
static int g_region_bottom = -1; /* viewport row of the scroll region's
                                  * bottom (= panel top - 1) */

/* Seek to the tracked content end and re-track after a write. Lock held. */
static void content_seek_write(const char *s, size_t n)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (g_content_y < 0) {
        if (!g_console_out
            || !GetConsoleScreenBufferInfo(g_hstdout, &csbi)) {
            out_write_unlocked(s, n); /* no console: write at the cursor */
            return;
        }
        g_content_x = csbi.dwCursorPosition.X;
        g_content_y = csbi.dwCursorPosition.Y;
    }
    if (g_console_out && GetConsoleScreenBufferInfo(g_hstdout, &csbi)
        && g_region_bottom > 0) {
        /* chat-style bottom alignment: when the transcript ends above the
         * region bottom, scroll the region down so output hugs the panel
         * and the spare rows live at the top (future scrollback). Once
         * aligned the region scrolls normally and the gap stays zero. */
        int rbottom = csbi.srWindow.Top + g_region_bottom - 1;
        int gap = rbottom - g_content_y;
        if (gap > 0) {
            if (gap > g_region_bottom)
                gap = g_region_bottom;
            char sd[24];
            int sn = snprintf(sd, sizeof sd, "\x1b[%dT", gap);
            out_write_unlocked(sd, (size_t)sn);
            g_content_y = (SHORT)(g_content_y + gap);
        }
    }
    if (g_console_out)
        SetConsoleCursorPosition(
            g_hstdout, (COORD){g_content_x, g_content_y});
    out_write_unlocked(s, n);
    if (g_console_out && GetConsoleScreenBufferInfo(g_hstdout, &csbi)) {
        g_content_x = csbi.dwCursorPosition.X;
        g_content_y = csbi.dwCursorPosition.Y;
    }
}

static void out_write(const char *s, size_t n)
{
    if (!n)
        return;
    AcquireSRWLockExclusive(&g_out_lock);
    if (g_dock && !g_no_seek)
        content_seek_write(s, n);
    else
        out_write_unlocked(s, n);
    ReleaseSRWLockExclusive(&g_out_lock);
}

/* Panel paint: write at the cursor, never seek to the content end. */
static void out_frame_write(const char *s, size_t n)
{
    if (!n)
        return;
    AcquireSRWLockExclusive(&g_out_lock);
    out_write_unlocked(s, n);
    ReleaseSRWLockExclusive(&g_out_lock);
}

static void out_frame_puts(const char *s)
{
    out_frame_write(s, strlen(s));
}

/* Panel paint printf; main thread only (composer, menu, picker). */
static void out_frame_printf(const char *fmt, ...)
{
    static struct buf b;
    va_list ap;
    va_start(ap, fmt);
    buf_reset(&b);
    buf_append_vf(&b, fmt, ap);
    va_end(ap);
    out_frame_write(b.p, b.len);
}

static void out_puts(const char *s)
{
    out_write(s, strlen(s));
}

/* out_printf scratch, one per thread (the agent thread writes the
 * transcript while the composer paints on the main thread); freed by
 * out_printf_thread_end so per-turn agent threads never leak it. */
static _Thread_local struct buf g_out_scratch;
static _Thread_local int g_out_scratch_used;

static void out_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    buf_reset(&g_out_scratch); /* the scratch keeps its capacity between
                                * calls, so the usual line formats in one
                                * pass into room that is already there */
    buf_append_vf(&g_out_scratch, fmt, ap);
    va_end(ap);
    g_out_scratch_used = 1;
    out_write(g_out_scratch.p, g_out_scratch.len);
}

/* Release the calling thread's out_printf scratch (agent thread exit). */
static void out_printf_thread_end(void)
{
    if (g_out_scratch_used) {
        buf_free(&g_out_scratch);
        g_out_scratch_used = 0;
    }
}

/* Fixed dock: rows 1..N-2 scroll the transcript (DECSTBM), row N-1 is the
 * composer bar, row N the status line. Both pinned rows keep their owner for
 * the whole session, so the input bar is always visible — even mid-turn. */

/* Turn clock and streamed-byte counter behind the status rows. */
static DWORD g_turn_start;    /* GetTickCount at turn start */
static unsigned long long g_stream_bytes; /* deltas this round */

/* "12s" / "2:05" — tenths are motion for their own sake. */
static void fmt_secs(char *dst, size_t cap, DWORD secs)
{
    if (secs < 60)
        snprintf(dst, cap, "%lus", (unsigned long)secs);
    else
        snprintf(dst, cap, "%lu:%02lu", (unsigned long)(secs / 60),
                 (unsigned long)(secs % 60));
}

/* "872" / "1.2k" / "3.4M" */
static void fmt_bytes(char *dst, size_t cap, unsigned long long n)
{
    if (n < 1024)
        snprintf(dst, cap, "%llu", n);
    else if (n < 1024 * 1024)
        snprintf(dst, cap, "%.1fk", (double)n / 1024);
    else
        snprintf(dst, cap, "%.1fM", (double)n / (1024 * 1024));
}

/* Copy src cut to max_cols display columns at UTF-8 char boundaries,
 * ending with "…" when anything was dropped. */
static void trunc_cols(char *dst, size_t cap, const char *src, int max_cols)
{
    size_t n = strlen(src), o = 0, i = 0;
    int w = 0, cut = 0;
    while (i < n && o + 8 < cap) {
        uint32_t cp;
        size_t clen = u8_step(src + i, n - i, &cp);
        int cw = u8_cp_width(cp);
        if (w + cw > max_cols) {
            cut = 1;
            break;
        }
        memcpy(dst + o, src + i, clen);
        o += clen;
        i += clen;
        w += cw;
    }
    if (cut)
        o += (size_t)snprintf(dst + o, cap - o, "…");
    dst[o] = '\0';
}

/* Shared braille frames: the wait spinner and the tool tick. */
static const char *SPIN_FRAMES[] = { "⠋", "⠙", "⠹", "⠸", "⠼",
                                     "⠴", "⠦", "⠧", "⠇", "⠏" };

/* --- input during a turn (the composer never sleeps) ---------------------- */

/* The composer runs on the main thread for the whole session; a turn
 * streams on the agent thread. Text submitted mid-turn is queued here:
 * Enter sets g_steer + g_cancel, the run unwinds, and turn_feed_queue
 * injects the text as the user turn the next request answers. All
 * state is guarded by g_out_lock. */

static struct buf g_queued;           /* pending new-input lines, \n separated */
static volatile LONG g_steer;         /* enter with content: inject + interrupt */
static char g_tick_label[160];        /* running tool for the status line */
static DWORD g_tick_start;            /* when the running tool started */
/* The arguments a tool call is still streaming. A big write can spend
 * minutes generating its content before the tool ever runs, and a row that
 * said only "思考中" the whole time reads as a hang, so the status line shows
 * live bytes and lines. Counters only: the row formats them at paint time. */
static char g_gen_tool[48];
static size_t g_gen_len, g_gen_lines;

/* Fixed dock: the composer panel pins to the bottom edge (rule + draft
 * window + hint + rule + status, 4..13 rows tall) and every painter writes
 * absolute rows; the scroll region ends above the tallest panel so
 * transcript output scrolls behind it and the panel never vanishes. */
static volatile LONG g_frame; /* spinner animation frame */
static struct buf g_dock_frame;

/* Build the pinned status row's text: spinner + phase during waits and
 * streaming, the running tool's label, the model name when idle. Both the
 * spinner thread and the composer frame render through this, so a keystroke
 * repaint never flickers the row back to the model name. */
static void status_line_build(char *line, size_t lcap, char *tail,
                              size_t tcap)
{
    int busy = (int)g_busy;
    tail[0] = '\0';
    if (busy == 1 && InterlockedCompareExchange(&g_cancel, 0, 0)) {
        snprintf(line, lcap,
                 "\x1b[36m⇣\x1b[0m \x1b[36m正在取消…\x1b[0m");
    } else if (g_tick_label[0] || (busy == 2 && g_gen_len)) {
        /* Either a running tool's label or, while a tool call's arguments
         * are still streaming, the live byte/line counters — formatted here,
         * once per painted frame, instead of once per delta. */
        char label[192];
        if (busy == 2 && g_gen_len) {
            char fb[24];
            fmt_bytes(fb, sizeof fb, (unsigned long long)g_gen_len);
            snprintf(label, sizeof label, "%s · 生成中 %s / %zu 行",
                     g_gen_tool[0] ? g_gen_tool : "工具", fb, g_gen_lines);
        } else {
            snprintf(label, sizeof label, "%s", g_tick_label);
        }
        char cut[160];
        trunc_cols(cut, sizeof cut, label,
                   g_term_cols - 40 > 8 ? g_term_cols - 40 : 8);
        snprintf(line, lcap, "\x1b[36m%s\x1b[0m \x1b[2m%s\x1b[0m",
                 SPIN_FRAMES[g_frame % 10], cut);
    } else if (busy == 1) {
        snprintf(line, lcap,
                 "\x1b[36m%s\x1b[0m \x1b[36m思考中\x1b[0m"
                 "\x1b[2m · Ctrl+C 中断\x1b[0m",
                 SPIN_FRAMES[g_frame % 10]);
    } else if (busy == 2) {
        const char *spin = SPIN_FRAMES[g_frame % 10];
        if (g_stream_bytes) {
            char fb[24];
            fmt_bytes(fb, sizeof fb, g_stream_bytes);
            snprintf(line, lcap,
                     "\x1b[36m%s\x1b[0m \x1b[36m生成中\x1b[0m"
                     "\x1b[2m · ↓%s\x1b[0m", spin, fb);
        } else
            snprintf(line, lcap,
                     "\x1b[36m%s\x1b[0m \x1b[36m生成中\x1b[0m", spin);
    } else {
        char model[160];
        trunc_cols(model, sizeof model,
                   g_status_model ? g_status_model : "(未设置)",
                   g_term_cols - 20 > 8 ? g_term_cols - 20 : 8);
        if (g_ctx_tokens > 0)
            snprintf(line, lcap, "\x1b[2m%s · ~%lluk ctx\x1b[0m", model,
                     (unsigned long long)(g_ctx_tokens / 1000));
        else
            snprintf(line, lcap, "\x1b[2m%s\x1b[0m", model);
    }
    if (busy) {
        char fs[16];
        DWORD since = (g_tick_label[0] || g_gen_len) ? g_tick_start
                                                     : g_turn_start;
        fmt_secs(fs, sizeof fs, (GetTickCount() - since) / 1000);
        snprintf(tail, tcap, "\x1b[2m · %s\x1b[0m", fs);
    }
}

/* args holds the whole accumulated buffer; from is where this delta began,
 * so line counting stays O(new bytes) instead of rescanning per delta.
 *
 * Counters only, on purpose: the row formats them at paint time. Formatting
 * here instead cost two snprintf plus an output-lock acquire on every
 * argument delta — 20,000 times for a 1.4MB streamed file write. */
static void gen_progress(const char *tool, const struct buf *args, size_t from)
{
    if (g_gen_len == 0 && g_gen_lines == 0 && args->len > from)
        g_tick_start = GetTickCount(); /* first fragment: start the clock */
    const char *p = args->p + from, *end = args->p + args->len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl)
            break;
        g_gen_lines++;
        p = nl + 1;
    }
    g_gen_len += args->len - from;
    if (!g_gen_tool[0] && tool && *tool)
        snprintf(g_gen_tool, sizeof g_gen_tool, "%s", tool);
}

/* The status line: spinner + phase during waits, live counters while
 * streaming, the running tool's label, the model name when idle. */
static void status_repaint(void)
{
    if (!g_emit_vt || !g_dock)
        return;
    AcquireSRWLockExclusive(&g_out_lock);
    /* save/restore the cursor in BUFFER coords: a CUP restore would land
     * somewhere else the moment the pane has scrollback (Top != 0) */
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    memset(&csbi, 0, sizeof csbi);
    int have_cur = g_console_out
        && GetConsoleScreenBufferInfo(g_hstdout, &csbi);
    SHORT cx = have_cur ? csbi.dwCursorPosition.X : 0;
    SHORT cy = have_cur ? csbi.dwCursorPosition.Y : 0;
    int row = g_term_rows; /* the panel's status row: last on screen */
    char line[512], tail[96];
    status_line_build(line, sizeof line, tail, sizeof tail);
    buf_reset(&g_dock_frame);
    buf_appendf(&g_dock_frame, "\x1b[%d;1H\x1b[2K%s%s\x1b[0K", row, line,
                tail);
    if (g_dock_frame.len)
        out_write_unlocked(g_dock_frame.p, g_dock_frame.len);
    if (have_cur)
        SetConsoleCursorPosition(g_hstdout, (COORD){cx, cy});
    ReleaseSRWLockExclusive(&g_out_lock);
}

/* User-message echo: the text wraps at the terminal width and every visual
 * row pads its deep-teal background out to the full width. The bar stops
 * one column short of the last column so no row trips the terminal's
 * pending-wrap state. */
static void user_bars_buf(struct buf *out, const char *text, size_t len)
{
    size_t cols = (size_t)g_term_cols;
    size_t wrap = cols > 4 ? cols - 1 : 1;
    buf_appends(out, "\x1b[48;2;36;66;80m");
    size_t i = 0, rs = 0, w = 0;
    while (i < len) {
        int brk = 0;
        if (text[i] == '\n') {
            brk = 1;
        } else {
            uint32_t cp;
            size_t cl = u8_step(text + i, len - i, &cp);
            size_t cw = (size_t)u8_cp_width(cp);
            if (w + cw > wrap && w > 0)
                brk = 1; /* w == 0: the char alone exceeds the row, keep it */
            if (!brk) {
                w += cw;
                i += cl;
                continue;
            }
        }
        buf_append_n(out, text + rs, i - rs);
        buf_append_spaces(out, wrap - w);
        buf_appends(out, "\x1b[0m\r\n\x1b[48;2;36;66;80m");
        if (text[i] == '\n')
            i++;
        rs = i;
        w = 0;
    }
    buf_append_n(out, text + rs, len - rs);
    buf_append_spaces(out, wrap - w);
    buf_appends(out, "\x1b[0m");
}

/* Echo a pending line as the user turn it becomes (same shape the
 * composer draws). Takes the line as a slice: callers hold it inside a
 * larger NUL-terminated buffer and must not pay a copy per line.
 * Runs on whichever thread feeds the conversation; out_write seeks to
 * the content end on the agent thread. */
static void user_line_show(const char *text, size_t n)
{
    if (g_emit_vt) {
        struct buf b = BUF_INIT;
        user_bars_buf(&b, text, n);
        buf_appends(&b, "\r\n");
        out_write(b.p, b.len);
        buf_free(&b);
    } else {
        out_printf("> %.*s\r\n", (int)n, text);
    }
}

/* Nap for about ms, with two things Sleep cannot give on this machine: a
 * wake at the millisecond asked for, and a wait somebody can cut short.
 * Sleep's floor here is one clock tick (measured: Sleep(10) sleeps 16.1 ms),
 * so anything polled on it notices finished work a tick late. A
 * high-resolution waitable timer (Win10 1607+; the manifest already requires
 * 1903) is per-object, so it does not raise the clock resolution for every
 * other process, and `wake` is waited on alongside it so an owner can end
 * the nap at once. Per thread, because two threads arming one timer would
 * cut each other short. The Sleep fallback costs a tick and nothing more. */
static _Thread_local HANDLE g_nap_timer;

static void kk_nap(DWORD ms, HANDLE wake)
{
    if (!g_nap_timer) {
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif
        g_nap_timer = CreateWaitableTimerExW(
            NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
            SYNCHRONIZE | 0x3 /* TIMER_MODIFY_STATE | TIMER_QUERY_STATE */);
        if (!g_nap_timer) {
            Sleep(ms < 10 ? 10 : ms);
            return;
        }
    }
    LARGE_INTEGER due; /* negative due time = relative, in 100 ns units */
    due.QuadPart = -(LONGLONG)ms * 10000;
    if (!SetWaitableTimer(g_nap_timer, &due, 0, NULL, NULL, FALSE)) {
        Sleep(ms < 10 ? 10 : ms);
        return;
    }
    HANDLE h[2];
    DWORD n = 0;
    h[n++] = g_nap_timer;
    if (wake)
        h[n++] = wake;
    WaitForMultipleObjects(n, h, FALSE, ms + 1000);
}

/* Release this thread's nap timer. The agent and spinner threads are created
 * per turn, so a per-thread handle left behind would pile up one handle per
 * turn for the rest of the session. */
static void nap_thread_end(void)
{
    if (g_nap_timer) {
        CancelWaitableTimer(g_nap_timer);
        CloseHandle(g_nap_timer);
        g_nap_timer = NULL;
    }
}

/* Wait spinner: the sole animator of the pinned status line, running for the
 * whole turn (wait, stream, tools) — the row belongs to it, so nothing can
 * fight it for pixels. Never paints without VT (pipes stay clean). */

/* Set by the turn-end path so the spinner stops napping out its frame before
 * it is joined: that nap was the gap between an answer ending and the
 * composer taking input again. Auto-reset, created on first use, lives as
 * long as the process. */
static HANDLE g_spinner_wake;

static DWORD WINAPI spinner_thread(LPVOID arg)
{
    (void)arg;
    for (;;) {
        int busy = (int)g_busy;
        if (busy == 0 || !g_emit_vt)
            break;
        InterlockedIncrement(&g_frame);
        status_repaint();
        kk_nap(90, g_spinner_wake);
    }
    nap_thread_end();
    return 0;
}

/* Wide-string helpers for Win32 boundary calls. The length form is the
 * primitive: passing the byte count saves a hidden strlen over a payload
 * that can be megabytes. */
static wchar_t *w_from_utf8_n(const char *s, size_t n)
{
    int c = MultiByteToWideChar(CP_UTF8, 0, s, (int)n, NULL, 0);
    if (c <= 0)
        return NULL;
    wchar_t *w = xmalloc((size_t)(c + 1) * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, s, (int)n, w, c);
    w[c] = L'\0';
    return w;
}

static wchar_t *w_from_utf8(const char *s)
{
    return w_from_utf8_n(s, strlen(s));
}

static char *utf8_from_w(const wchar_t *w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0)
        return NULL;
    char *s = xmalloc((size_t)n);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

/* ==========================================================================
 * 4b. http — WinHTTP streaming POST
 * ========================================================================== */

/* Streaming response callback: return 0 to continue, nonzero to abort. */
typedef int (*http_stream_cb)(const char *bytes, size_t n, void *user);

/* The session and connection are cached process-wide: WinHTTP pools
 * keep-alive connections per session, so reusing them skips the TCP+TLS
 * handshake on every model turn — and a tool loop makes several requests per
 * user turn. HTTP only runs on the agent thread, so no lock. */
static HINTERNET g_http_session;
static HINTERNET g_http_connect;
static char *g_http_host;      /* cache key: narrow host + port + scheme */
static int g_http_port;
static int g_http_https;

static HINTERNET http_session(void)
{
    if (!g_http_session) {
        g_http_session = WinHttpOpen(L"kk/0.1",
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
        if (!g_http_session)
            g_http_session = WinHttpOpen(L"kk/0.1",
                                         WINHTTP_ACCESS_TYPE_NO_PROXY,
                                         WINHTTP_NO_PROXY_NAME,
                                         WINHTTP_NO_PROXY_BYPASS, 0);
    }
    return g_http_session;
}

/* Drop the pooled connection: the server closed it, or a request on it
 * failed and its state is unknown. */
static void http_disconnect(void)
{
    if (g_http_connect) {
        WinHttpCloseHandle(g_http_connect);
        g_http_connect = NULL;
    }
}

static HINTERNET http_connect(const char *host, int port, int https)
{
    if (g_http_connect && g_http_port == port && g_http_https == https
        && g_http_host && strcmp(g_http_host, host) == 0)
        return g_http_connect;
    http_disconnect();
    free(g_http_host);
    g_http_host = NULL;
    wchar_t *whost = w_from_utf8(host);
    if (!whost)
        return NULL;
    g_http_connect = WinHttpConnect(http_session(), whost,
                                    (INTERNET_PORT)port, 0);
    free(whost);
    if (g_http_connect) {
        g_http_host = xstrdup(host);
        g_http_port = port;
        g_http_https = https;
    }
    return g_http_connect;
}

/* Split scheme://host[:port]/path. Returns 0 on success. */
static int http_split_url(const char *url, int *https, char **host, int *port,
                          char **path)
{
    if (strncmp(url, "https://", 8) == 0) {
        *https = 1;
        url += 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        *https = 0;
        url += 7;
    } else {
        return -1;
    }
    const char *hend = url;
    while (*hend && *hend != ':' && *hend != '/')
        hend++;
    if (hend == url)
        return -1;
    const char *path_start = (*hend == '/') ? hend : "/";
    *path = xstrdup(*hend ? path_start : "/");
    size_t hlen = (size_t)(hend - url);
    char *h = xstrndup(url, hlen);
    *host = h;
    if (*hend == ':') {
        const char *ps = hend + 1;
        char *end;
        long v = strtol(ps, &end, 10);
        if (end == ps || v <= 0 || v > 65535 || (*end && *end != '/')) {
            free(*host);
            free(*path);
            return -1;
        }
        *port = (int)v;
    } else {
        *port = *https ? 443 : 80;
    }
    return 0;
}

/* Streaming POST. Returns the HTTP status (200 = streamed via cb), 0 on a
 * transport error, or -1 when cancelled. On any non-200 the response body is
 * returned through *body_out (heap; caller frees) for error reporting.
 * body_len is passed in: the request is already a sized buffer, and a
 * strlen over a multi-hundred-KB body every round was pure re-scan. */
static int http_post_stream(const char *url, const char *auth_key,
                            const char *body, size_t body_len,
                            long connect_timeout_ms, long idle_timeout_ms,
                            http_stream_cb cb, void *user, char **body_out)
{
    *body_out = NULL;
    int https, port;
    char *host, *path;
    if (http_split_url(url, &https, &host, &port, &path) != 0) {
        *body_out = xstrdup("invalid base_url (want http(s)://host[:port]/path)");
        return 0;
    }

    int result = 0;
    wchar_t *wpath = NULL, *whdrs = NULL;
    HINTERNET request = NULL;
    char *resp_all = NULL;
    size_t resp_len = 0, resp_cap = 0;

    HINTERNET session = http_session();
    if (!session) {
        *body_out = xstrdup("WinHttpOpen failed");
        goto out;
    }
    /* The host needs no wide copy of its own: WinHttpConnect widens it again,
     * against the connection handle it caches. Asking the converter for the
     * size answers the only question we have here — is this valid UTF-8 —
     * without an allocation and a conversion on every request. */
    int host_ok = MultiByteToWideChar(CP_UTF8, 0, host, (int)strlen(host),
                                      NULL, 0) > 0;
    wpath = w_from_utf8(path);
    if (!host_ok || !wpath) {
        /* xmalloc fatals on real exhaustion, so NULL here only ever means
         * the bytes were not valid UTF-8 */
        *body_out = xstrdup("base_url is not valid UTF-8");
        goto out;
    }

    {
        struct buf hdrs = BUF_INIT;
        buf_appends(&hdrs, "Content-Type: application/json\r\n");
        if (auth_key && *auth_key)
            buf_appendf(&hdrs, "Authorization: Bearer %s\r\n", auth_key);
        whdrs = w_from_utf8(hdrs.p);
        buf_free(&hdrs);
        if (!whdrs) {
            *body_out = xstrdup("api_key is not valid UTF-8");
            goto out;
        }
    }

    DWORD wire_len = (DWORD)body_len;
    DWORD t_send = GetTickCount();
    for (int attempt = 0;; attempt++) {
        HINTERNET connect = http_connect(host, port, https);
        if (!connect) {
            *body_out = xasprintf("cannot connect to %s:%d (WinHttp error %lu)",
                                  host, port, GetLastError());
            goto out;
        }
        request = WinHttpOpenRequest(connect, L"POST", wpath, NULL,
                                     WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     https ? WINHTTP_FLAG_SECURE : 0);
        if (!request) {
            *body_out = xstrdup("WinHttpOpenRequest failed");
            goto out;
        }
        WinHttpSetTimeouts(request, 15000, (int)connect_timeout_ms, 30000,
                           (int)idle_timeout_ms);
        if (!WinHttpAddRequestHeaders(request, whdrs, (DWORD)-1L,
                                      WINHTTP_ADDREQ_FLAG_ADD)) {
            *body_out = xstrdup("WinHttpAddRequestHeaders failed");
            goto out;
        }
        if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                (LPVOID)body, wire_len, wire_len, 0)) {
            /* a pooled keep-alive connection the server already closed
             * fails right here; drop it and rebuild exactly once — but only
             * when the first attempt failed FAST. A refused connect costs
             * the OS ~2s and a blackholed one the full connect timeout, and
             * a second identical try then just doubles the wait before the
             * same error: slow failures are the network's answer, not a
             * stale socket's. */
            WinHttpCloseHandle(request);
            request = NULL;
            http_disconnect();
            if (attempt == 0 && GetTickCount() - t_send < 5000)
                continue;
            *body_out = xasprintf("send failed (WinHttp error %lu)",
                                  GetLastError());
            goto out;
        }
        break;
    }
    if (!WinHttpReceiveResponse(request, NULL)) {
        *body_out = xasprintf("no response (WinHttp error %lu)", GetLastError());
        goto out;
    }

    DWORD status = 0, size = sizeof status;
    WinHttpQueryHeaders(request,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                        WINHTTP_NO_HEADER_INDEX);

    for (;;) {
        if (InterlockedCompareExchange(&g_cancel, 0, 0)) {
            result = -1;
            /* aborted mid-response: the pooled connection is in an
             * unknown state, so don't hand it to the next request */
            http_disconnect();
            goto out;
        }
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(request, &avail)) {
            *body_out = xasprintf("connection lost (WinHttp error %lu)",
                                  GetLastError());
            http_disconnect();
            goto out;
        }
        if (avail == 0)
            break;
        char tmp[262144]; /* 256KB per read: a 2MB stream pays 8 read
                           * round-trips instead of 128 */
        DWORD read = 0;
        if (avail > sizeof tmp)
            avail = sizeof tmp;
        if (!WinHttpReadData(request, tmp, avail, &read)) {
            *body_out = xasprintf("connection lost (WinHttp error %lu)",
                                  GetLastError());
            http_disconnect();
            goto out;
        }
        if (read == 0)
            break;
        if (status == 200) {
            if (cb(tmp, read, user) != 0) {
                result = -1;
                /* the callback bailed mid-body: same rule as the loop-top
                 * check, a half-read response must not be pooled */
                http_disconnect();
                goto out;
            }
        } else {
            /* error body: accumulate whole thing for reporting */
            if (resp_len + read > resp_cap) {
                resp_cap = (resp_len + read) * 2 + 1024;
                resp_all = xrealloc(resp_all, resp_cap);
            }
            memcpy(resp_all + resp_len, tmp, read);
            resp_len += read;
        }
    }
    if (status != 200) {
        if (!resp_all)
            resp_all = xstrdup("");
        resp_all[resp_len] = '\0';
        *body_out = resp_all;
        resp_all = NULL;
    }
    result = (int)status;

out:
    free(resp_all);
    if (request)
        WinHttpCloseHandle(request);
    /* session and pooled connection stay cached for the next request */
    free(whdrs);
    free(wpath);
    free(host);
    free(path);
    return result;
}

/* ==========================================================================
 * 5. markdown — streaming renderer with an append-only painter
 * ========================================================================== *
 *
 * Two channels feed the same painter machinery:
 *   - think channel: preformatted (wrap only), dim + italic, "▍ " prefix
 *   - text channel:  markdown inline styles + block structure
 *
 * The painter is append-only: complete physical rows are written once with
 * CRLF and never touched again (native scrollback stays intact). Only the
 * pending (last, unterminated) row is repainted in place with CR + ESC[K.
 * Rows hard-wrap at the usable width, so a late delta can never change an
 * already-committed row. Code fences are hard-wrapped too (spaces preserved)
 * and are line-buffered so the closing fence can be recognized before
 * anything is emitted. GFM tables are line-buffered the same way: the
 * complete block renders as an aligned grid, reflows into records when too
 * wide, or falls back to a verbatim render when a cell holds a literal `|`.
 */

#define PREFIX_THINK "\x1b[2m▍ \x1b[0m"
#define PREFIX_QUOTE "\x1b[2m│ \x1b[0m"
#define PREFIX_CODE "\x1b[2m│ \x1b[0m"

/* Plain markers when styling is off, so scripted pipe output stays clean. */
static const char *vt_or(const char *vt, const char *plain)
{
    return g_emit_vt ? vt : plain;
}

struct inline_state {
    int bold, italic, strike, code, under;
};

/* Compose one SGR sequence for a style set; the channel's base flags are
 * re-applied after the reset. seq must hold >=56 bytes, which is what both
 * callers declare. Built byte by byte: the printf round-trip ran on every
 * style toggle. */
static void compose_sgr(char *seq, const char *base_flags,
                        const struct inline_state *st)
{
    size_t n = 0;
    seq[n++] = '\x1b';
    seq[n++] = '[';
    seq[n++] = '0';
    while (*base_flags)
        seq[n++] = *base_flags++;
    if (st->bold) {
        seq[n++] = ';';
        seq[n++] = '1';
    }
    if (st->italic) {
        seq[n++] = ';';
        seq[n++] = '3';
    }
    if (st->under) {
        seq[n++] = ';';
        seq[n++] = '4';
    }
    if (st->strike) {
        seq[n++] = ';';
        seq[n++] = '9';
    }
    if (st->code) {
        memcpy(seq + n, ";48;2;44;44;54", 14);
        n += 14;
    }
    seq[n++] = 'm';
    seq[n] = '\0';
}

struct painter {
    struct buf pending;         /* styled bytes of the uncommitted row */
    size_t pending_width;       /* display columns, prefix+indent included */
    size_t leading;             /* console-only bytes folded in front of
                                 * pending (the row-start erase) */
    int row_open;               /* a row is open (lazily started on content) */
    int row_shown;              /* the open row is on screen */
    size_t shown;               /* bytes of pending already on screen */
    int row_indent;             /* columns skipped when a row wraps */
    int have_sgr;               /* the style is open in the pending buffer */
    const char *base_flags;     /* SGR params re-applied after every reset */
    const char *prefix;         /* per-row prefix (may embed SGR), or NULL */
    size_t prefix_bytes;
    int prefix_cols;            /* display columns of the prefix */
    int cols;                   /* terminal columns this painter wraps to */
    int usable;                 /* columns available for content */
    struct inline_state *live;  /* live style state this painter renders */
};

static void painter_set_prefix(struct painter *p, const char *prefix)
{
    if (p->prefix == prefix)
        return; /* same literal as last time (code rows re-set it per line):
                 * its metrics are already measured */
    p->prefix = prefix;
    p->prefix_bytes = prefix ? strlen(prefix) : 0;
    /* prefixes change rarely; rows start constantly — measure once here
     * instead of decoding the prefix at every row start */
    p->prefix_cols = (int)(prefix ? visible_width(prefix, p->prefix_bytes) : 0);
}

static void painter_init(struct painter *p, const char *base_flags,
                         const char *prefix, struct inline_state *live)
{
    memset(p, 0, sizeof *p);
    p->base_flags = base_flags;
    painter_set_prefix(p, prefix);
    p->live = live;
}

/* Recompute usable columns. Runs on width changes and at every row start:
 * quote/code prefixes are swapped at runtime, and a row that does not count
 * its prefix overflows the terminal — the early auto-wrap then desyncs the
 * painter and the cursor jumps rows. */
static void painter_layout(struct painter *p)
{
    p->usable = p->cols - 1 - p->prefix_cols;
    if (p->usable < 10)
        p->usable = 10;
}

static void painter_set_width(struct painter *p, int cols)
{
    p->cols = cols;
    painter_layout(p);
}

static void painter_emit_sgr(struct painter *p, struct buf *sink)
{
    if (!g_emit_vt)
        return;
    if (p->have_sgr)
        return; /* style already open in the pending buffer: hot path */
    p->have_sgr = 1;
    char seq[56];
    compose_sgr(seq, p->base_flags, p->live);
    buf_appends(sink, seq);
}

static void painter_start_row(struct painter *p)
{
    /* a resize mid-stream: the composer keeps polling the size, so wrap at
     * the new width from this row on. Committed rows keep their old wrap —
     * the console reflows its own buffer on resize anyway. Only the width is
     * set here: painter_layout runs once, on the line below. */
    if (p->cols != g_term_cols)
        p->cols = g_term_cols;
    painter_layout(p);
    p->row_open = 1;
    p->row_shown = 0;
    p->shown = 0;
    p->leading = 0;
    buf_reset(&p->pending);
    if (p->prefix)
        buf_append_n(&p->pending, p->prefix, p->prefix_bytes);
    int indent = p->row_indent;
    if (indent > p->usable / 2)
        indent = p->usable / 2; /* degenerate deep indent: keep rows sane */
    if (indent > 0)
        buf_append_spaces(&p->pending, (size_t)indent);
    p->pending_width = (size_t)p->prefix_cols
        + (size_t)(indent > 0 ? indent : 0);
    p->have_sgr = 0;
}

/* Rows start lazily: prefix/indent are read when the first content of the
 * row arrives, so a probe can set them before anything is drawn. */
static void painter_ensure_row(struct painter *p)
{
    if (!p->row_open)
        painter_start_row(p);
}

static void painter_close_row(struct painter *p)
{
    p->row_open = 0;
    p->row_shown = 0;
    p->pending_width = 0;
    p->leading = 0;
    buf_reset(&p->pending);
}

static void painter_append_styled(struct painter *p, const char *s, size_t n);

/* Append one codepoint to the pending row with the open style applied. */
static void painter_append_cp_styled(struct painter *p, uint32_t cp)
{
    char tmp[4];
    painter_append_styled(p, tmp, u8_encode(cp, tmp)); /* owns wrapping */
}

/* Streaming paint throttle: deltas land in the pending buffer (never
 * lost) and the console only sees a frame every ~20ms. Commit paths call
 * painter_screen directly, so row boundaries always flush in full. */
static DWORD g_last_paint;

static void painter_screen(struct painter *p);

static void painter_screen_throttled(struct painter *p)
{
    DWORD now = now_ms();
    if (now - g_last_paint < 20)
        return; /* still buffered; the next delta or commit will paint */
    g_last_paint = now;
    painter_screen(p);
}

/* Bring the screen in sync with the pending row. The view only ever
 * grows (append-only), so painting writes just the new suffix bytes at
 * the cursor: no erase, no flicker. The row-start CR+erase (clearing
 * wait-spinner residue, aligning col 0) is folded in FRONT of the
 * pending bytes, so a freshly started row also lands in one write. */
static void painter_screen(struct painter *p)
{
    if (!g_emit_vt)
        return; /* pipes get rows at commit time (no erase/rewrite) */
    if (!p->row_open && p->pending.len == 0)
        return;
    if (p->shown == p->pending.len && p->shown > 0)
        return; /* already fully painted */
    painter_ensure_row(p);
    if (p->shown == 0 && !p->leading) {
        buf_reserve(&p->pending, 5);
        memmove(p->pending.p + 5, p->pending.p, p->pending.len);
        memcpy(p->pending.p, "\r\x1b[0K", 5);
        p->pending.len += 5;
        p->pending.p[p->pending.len] = '\0';
        p->leading = 5;
    }
    if (p->shown < p->pending.len) {
        out_write(p->pending.p + p->shown, p->pending.len - p->shown);
        p->shown = p->pending.len;
    }
    p->row_shown = 1;
}

/* Commit the pending row: sync the screen and end the line. The row
 * content is final by the time this runs. The line terminator rides in
 * the pending buffer so a commit costs ONE console write, not two —
 * line-heavy streams commit per row. */
static void painter_commit_row(struct painter *p)
{
    if (!g_emit_vt) {
        buf_append_lit(&p->pending, "\r\n");
        out_write(p->pending.p, p->pending.len);
        painter_close_row(p);
        return;
    }
    buf_append_lit(&p->pending, "\x1b[0m\r\n"); /* close any open style: no
                                                 * bleed into the next row */
    painter_screen(p);
    painter_close_row(p);
}

static int painter_row_has_content(const struct painter *p)
{
    size_t fixed = p->prefix_bytes + p->leading
        + (size_t)(p->row_indent > 0 ? p->row_indent : 0);
    return p->pending.len > fixed || p->row_shown;
}

/* Append styled bytes to the pending row, hard-wrapping when it fills.
 * Content is only ever appended to an OPEN row with room: the wrap path
 * commits, re-opens the row and re-opens the style BEFORE appending, or
 * the next ensure_row would wipe what was just buffered. */
static void painter_append_styled(struct painter *p, const char *s, size_t n)
{
    size_t at = 0;
    while (at < n) {
        painter_ensure_row(p);
        painter_emit_sgr(p, &p->pending); /* cached: no-op when style open */
        int room = p->usable - (int)p->pending_width;
        if (room <= 0) {
            painter_commit_row(p);
            painter_ensure_row(p);
            painter_emit_sgr(p, &p->pending);
            room = p->usable - (int)p->pending_width;
            if (room <= 0)
                room = 1; /* degenerate width: keep making progress */
        }
        size_t take_bytes = 0, take_width = 0;
        if ((unsigned char)s[at] >= 0x20 && (unsigned char)s[at] < 0x80) {
            /* ASCII fast path: every byte decodes to itself at width 1,
             * so up to `room` bytes go in one scan + one memcpy — model
             * output is mostly ASCII and this skips the per-codepoint
             * decode/width calls entirely */
            size_t lim = at + (size_t)room;
            if (lim > n)
                lim = n;
            take_bytes = ascii_run(s + at, lim - at);
            take_width = take_bytes;
        } else {
            size_t i = at;
            while (i < n) {
                size_t clen, cw;
                if ((unsigned char)s[i] == 0x1B) {
                    size_t lim = i + 32;
                    if (lim > n)
                        lim = n;
                    size_t j = i + 1;
                    while (j < lim && s[j] != 'm')
                        j++;
                    if (j < lim) { /* SGR: zero width */
                        clen = j + 1 - i;
                        cw = 0;
                    } else { /* stray ESC: literal byte, width 1 */
                        clen = 1;
                        cw = 1;
                    }
                } else {
                    uint32_t cp;
                    clen = u8_step(s + i, n - i, &cp);
                    cw = (size_t)u8_cp_width(cp);
                }
                if (take_width + cw > (size_t)room)
                    break;
                take_bytes += clen;
                take_width += cw;
                i += clen;
            }
            if (take_bytes == 0) {
                /* the next item does not fit the row: commit and re-walk
                 * it on a fresh row (a single codepoint is always narrower
                 * than a fresh row, so this makes progress) */
                painter_commit_row(p);
                continue; /* loop top re-opens the row and the style */
            }
        }
        buf_append_n(&p->pending, s + at, take_bytes);
        p->pending_width += take_width;
        at += take_bytes;
    }
}


/* Plain streaming feed (think channel): direct append, hard wrap. Runs of
 * well-formed codepoints go to the painter as RAW bytes in one call — it
 * decodes each codepoint once, for width and wrap. */
static void painter_feed_plain(struct painter *p, const char *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        /* printable ASCII run (never \n or \t: both sit below 0x20) */
        if ((unsigned char)s[i] >= 0x20 && (unsigned char)s[i] < 0x80) {
            size_t start = i;
            i += ascii_run(s + i, n - i);
            painter_append_styled(p, s + start, i - start);
            continue;
        }
        uint32_t cp;
        size_t clen = u8_decode(s + i, n - i, &cp);
        if (clen == 0) {
            painter_append_cp_styled(p, 0xFFFD); /* invalid byte */
            i++;
            continue;
        }
        if (cp == '\n') {
            painter_commit_row(p);
            i += clen;
            continue;
        }
        if (cp == '\t') {
            painter_append_styled(p, "    ", 4);
            i += clen;
            continue;
        }
        /* multi-byte codepoint: batch the whole well-formed run */
        size_t start = i;
        i += clen;
        while (i < n) {
            size_t l2 = u8_decode(s + i, n - i, &cp);
            if (l2 == 0 || cp == '\n' || cp == '\t')
                break;
            i += l2;
        }
        painter_append_styled(p, s + start, i - start);
    }
    painter_screen_throttled(p);
}

/* Emit one complete pre-styled line as a row (table cells, code lines). */
static void painter_paint_line(struct painter *p, const char *s, size_t n)
{
    painter_ensure_row(p);
    painter_emit_sgr(p, &p->pending);
    painter_append_styled(p, s, n);
    painter_commit_row(p);
}

/* ========================================================================== *
 * text channel: markdown blocks + inline markers
 * ========================================================================== */

enum channel {
    CH_NONE = 0,
    CH_THINK,
    CH_TEXT,
};

struct renderer {
    enum channel channel;
    struct painter think_p, text_p;
    struct painter *cur;
    struct inline_state text_st;

    /* inline marker lookahead */
    int hold;   /* held marker codepoint, 0 = none */
    int prev_c; /* last committed text codepoint */

    /* block state */
    int fence;               /* 0 off, 1 collecting language, 2 inside code */
    char fence_marker;
    int fence_run;
    struct buf fence_lang;   /* raw language tag bytes */
    struct buf fence_line;   /* raw current code line */
    struct buf probe;        /* line-start marker probe (raw bytes) */
    size_t probe_cp;         /* codepoints held in probe */
    int probe_indent;        /* leading spaces seen */
    int line_start;          /* at the start of a logical line */

    /* GFM tables: line-buffered like fences — column sizing needs the
     * whole block before the first row is committed */
    int tbl_state;           /* TBL_* */
    int tbl_replay;          /* replaying refused lines: probe must not
                              * re-enter table collection */
    struct buf tbl_line;     /* row being accumulated */
    struct buf tbl_rows;     /* completed rows, '\n'-joined */

    /* task lists: after a list marker, watch for "[ ]" / "[x] " */
    int task_scan;           /* 0 off, 1..4 lookahead phase */
    uint32_t task_c[3];      /* withheld codepoints */
    int task_n;
};

static void rd_feed_char(struct renderer *r, uint32_t c);

static struct inline_state *zero_state(void)
{
    static struct inline_state zs;
    return &zs;
}

/* Contract: r must be zeroed (static storage) or previously initialized
 * — the buf_free calls release the previous campaign's buffers. */
static void renderer_init(struct renderer *r)
{
    buf_free(&r->fence_lang);
    buf_free(&r->fence_line);
    buf_free(&r->probe);
    buf_free(&r->tbl_line);
    buf_free(&r->tbl_rows);
    /* the painters' pending buffers were wiped by the memset below
     * without their bytes ever being freed — one leak per round */
    buf_free(&r->think_p.pending);
    buf_free(&r->text_p.pending);
    memset(r, 0, sizeof *r);
    painter_init(&r->think_p, ";2;3", vt_or(PREFIX_THINK, "▍ "), zero_state());
    painter_init(&r->text_p, "", NULL, &r->text_st);
    r->cur = &r->text_p;
    r->channel = CH_NONE;
}

static void renderer_set_width(struct renderer *r)
{
    painter_set_width(&r->think_p, g_term_cols);
    painter_set_width(&r->text_p, g_term_cols);
}

/* --- text-channel emit helpers ------------------------------------------ */

static void rd_out_cp(struct renderer *r, uint32_t cp)
{
    painter_append_cp_styled(r->cur, cp);
}

static void rd_toggle(struct renderer *r, int *flag)
{
    *flag = !*flag;
    r->cur->have_sgr = 0; /* force re-emit before the next output */
}

static int cp_is_boundary(uint32_t c)
{
    /* CJK punctuation compares against codepoints: multi-byte character
     * constants evaluate to the raw UTF-8 byte triple, never the cp */
    return c == 0 || c == ' ' || c == '\t' || c == ',' || c == '.' || c == ';'
        || c == '!' || c == '?' || c == ')' || c == '(' || c == ':' || c == '"'
        || c == '\'' || c == 0xFF0C || c == 0x3002 || c == 0xFF01
        || c == 0xFF1F || c == 0xFF1A || c == 0xFF1B || c == 0xFF09
        || c == 0xFF08 || c == 0x3001;
}

/* A codepoint with no marker/block meaning: batches into plain runs. */
static int rd_plain_cp(uint32_t cp)
{
    if (cp >= 0x80)
        return 1; /* any multi-byte codepoint */
    return cp >= 0x20 && cp != 0x7F && cp != '*' && cp != '_' && cp != '`'
        && cp != '~' && cp != '\\';
}

static int rd_is_ascii_punct(uint32_t c)
{
    return (c >= '!' && c <= '/') || (c >= ':' && c <= '@')
        || (c >= '[' && c <= '`') || (c >= '{' && c <= '~');
}

/* Resume the inline path with the lookahead codepoint (0 = line ended). */
static void rd_resume(struct renderer *r, uint32_t c)
{
    if (c)
        rd_feed_char(r, c);
}

/* Resolve the held marker given the next codepoint (0 = line ended). */
static void rd_resolve_hold(struct renderer *r, uint32_t c)
{
    int h = r->hold;
    r->hold = 0;
    if (h == '\\') {
        /* backslash escape: an ASCII punctuation char loses its marker
         * meaning and prints literally */
        if (c && rd_is_ascii_punct(c)) {
            rd_out_cp(r, c);
            r->prev_c = (int)c;
            return;
        }
        rd_out_cp(r, (uint32_t)'\\');
        r->prev_c = '\\';
        rd_resume(r, c);
        return;
    }
    if (h == '`') {
        rd_toggle(r, &r->text_st.code);
        rd_resume(r, c);
        return;
    }
    if (h == '~') {
        if (c == '~') {
            rd_toggle(r, &r->text_st.strike);
            return;
        }
        rd_out_cp(r, (uint32_t)'~');
        rd_resume(r, c);
        return;
    }
    /* '*' / '_' */
    if ((h == '*' || h == '_') && c == (uint32_t)h) {
        rd_toggle(r, &r->text_st.bold);
        return;
    }
    int open_boundary = r->prev_c == 0 || cp_is_boundary((uint32_t)r->prev_c);
    int close_boundary = cp_is_boundary(c);
    if (h == '*') {
        if (r->text_st.italic) {
            rd_toggle(r, &r->text_st.italic); /* closing */
            rd_resume(r, c);
            return;
        }
        if (!open_boundary || (c && close_boundary)) {
            rd_out_cp(r, (uint32_t)'*'); /* literal */
            rd_resume(r, c);
            return;
        }
        rd_toggle(r, &r->text_st.italic);
        rd_resume(r, c);
        return;
    }
    /* '_' */
    if (r->text_st.italic && (c == 0 || close_boundary)) {
        rd_toggle(r, &r->text_st.italic);
        rd_resume(r, c);
        return;
    }
    if (!r->text_st.italic && open_boundary && c && !close_boundary) {
        rd_toggle(r, &r->text_st.italic);
        return;
    }
    rd_out_cp(r, (uint32_t)'_');
    rd_resume(r, c);
}

/* Drop a pending task-list lookahead, printing what was withheld. */
static void rd_task_flush(struct renderer *r)
{
    for (int k = 0; k < r->task_n; k++)
        rd_out_cp(r, r->task_c[k]);
    r->task_n = 0;
    r->task_scan = 0;
}

/* Task-list lookahead after a list marker: "[ ]" renders ☐, "[x]" renders ✓
 * (ki's presentation). Withheld codepoints flush literally on a mismatch. */
static void rd_task_char(struct renderer *r, uint32_t c)
{
    if (r->task_scan == 1) {
        if (c == '[') {
            r->task_c[0] = c;
            r->task_n = 1;
            r->task_scan = 2;
            return;
        }
    } else if (r->task_scan == 2) {
        if (c == ' ' || c == 'x' || c == 'X') {
            r->task_c[1] = c;
            r->task_n = 2;
            r->task_scan = 3;
            return;
        }
    } else if (r->task_scan == 3) {
        if (c == ']') {
            r->task_c[2] = c;
            r->task_n = 3;
            r->task_scan = 4;
            return;
        }
    } else { /* phase 4: "[ ]"/"[x]" withheld, need a separator space */
        if (c == ' ' || c == '\t') {
            int done = r->task_c[1] == 'x' || r->task_c[1] == 'X';
            const char *mark = done ? vt_or("\x1b[32m✓\x1b[0m", "✓")
                                    : vt_or("\x1b[2m☐\x1b[0m", "☐");
            painter_append_styled(r->cur, mark, strlen(mark));
            r->cur->have_sgr = 0; /* the marker closed with a reset */
            r->task_scan = 0;
            r->task_n = 0;
            rd_feed_char(r, c); /* the separator space, wrap-checked */
            return;
        }
    }
    rd_task_flush(r);
    rd_feed_char(r, c);
}

/* Feed one text-channel codepoint through inline processing. */
static void rd_feed_char(struct renderer *r, uint32_t c)
{
    struct painter *p = r->cur;
    if (r->task_scan) {
        rd_task_char(r, c);
        return;
    }
    if (r->hold) {
        rd_resolve_hold(r, c);
        return;
    }
    if (c == '\\' || c == '*' || c == '_' || c == '`' || c == '~') {
        r->hold = (int)c;
        return;
    }
    if (c == ' ' || c == '\t') {
        /* route through append_styled so runs near the row edge wrap */
        painter_append_styled(p, c == '\t' ? "    " : " ",
                              c == '\t' ? 4 : 1);
        r->prev_c = ' ';
        return;
    }
    rd_out_cp(r, c);
    r->prev_c = (int)c;
}

/* --- probe: block decisions at line start -------------------------------- */

static void rd_line_reset(struct renderer *r);

/* Flush the probe's held codepoints through the inline path. */
static void rd_probe_flush(struct renderer *r)
{
    struct buf b = r->probe;
    memset(&r->probe, 0, sizeof r->probe);
    size_t i = 0;
    while (i < b.len) {
        uint32_t cp;
        size_t clen = u8_step(b.p + i, b.len - i, &cp);
        rd_feed_char(r, cp);
        i += clen;
    }
    buf_free(&b);
    r->probe_cp = 0;
}

/* Emit a horizontal rule row. */
static void rd_emit_hr(struct renderer *r)
{
    struct painter *p = r->cur;
    painter_close_row(p);
    if (g_emit_vt)
        buf_append_lit(&p->pending, "\x1b[2m");
    int cols = p->usable < 40 ? p->usable : 40;
    if (cols > 0) {
        /* "─" is one 3-byte glyph: cols columns are a prefix of its 40-fold
         * repetition, so the whole rule is ONE append */
        static const char hr[] =
            "────────────────────────────────────────────────";
        buf_append_n(&p->pending, hr, (size_t)cols * 3);
    }
    if (g_emit_vt)
        buf_append_lit(&p->pending, "\x1b[0m");
    painter_commit_row(p);
}

/* Emit the code fence header row (language tag). */
static void rd_fence_header(struct renderer *r)
{
    struct painter *p = r->cur;
    painter_ensure_row(p);
    buf_appends(&p->pending, vt_or("\x1b[2m── ", "── "));
    if (r->fence_lang.len)
        buf_append_n(&p->pending, r->fence_lang.p, r->fence_lang.len);
    if (g_emit_vt)
        buf_appends(&p->pending, "\x1b[0m");
    painter_commit_row(p);
}

static void rd_fence_close(struct renderer *r)
{
    r->fence = 0;
    r->fence_marker = 0;
    r->fence_run = 0;
    r->fence_lang.len = 0;
    r->fence_line.len = 0;
}

/* Feed one codepoint while inside a fence. */
static void rd_fence_char(struct renderer *r, uint32_t c)
{
    if (r->fence == 1) {
        /* collecting the language tag on the opening line */
        if (c == '\n') {
            rd_fence_header(r);
            r->fence = 2;
            r->fence_line.len = 0;
        } else {
            buf_append_cp(&r->fence_lang, c);
        }
        return;
    }
    /* inside code: line-buffer to detect the closing fence */
    if (c == '\n') {
        struct str line = { r->fence_line.p, r->fence_line.len };
        /* trim trailing \r / spaces */
        while (line.n > 0 && (line.p[line.n - 1] == '\r' || line.p[line.n - 1] == ' '))
            line.n--;
        size_t run = 0;
        size_t k = 0;
        while (k < line.n && line.p[k] == r->fence_marker) {
            run++;
            k++;
        }
        int only_ws_after = 1;
        for (size_t j = k; j < line.n; j++) {
            if (line.p[j] != ' ' && line.p[j] != '\t')
                only_ws_after = 0;
        }
        if (run >= (size_t)r->fence_run && only_ws_after) {
            rd_fence_close(r);
        } else {
            struct painter *p = r->cur;
            painter_set_prefix(p, vt_or(PREFIX_CODE, "│ "));
            /* empty code lines still show the prefix */
            painter_paint_line(p, line.p, line.n);
            painter_set_prefix(p, NULL);
        }
        r->fence_line.len = 0;
        return;
    }
    buf_append_cp(&r->fence_line, c);
}

/* --- GFM tables ------------------------------------------------------------
 * Rows buffer whole because column sizing needs the complete block. A table
 * opens only when a header row is followed by a `:?-+:?` delimiter row with
 * matching column count. Aligned grids are emitted when the natural width
 * fits the painter; otherwise body rows reflow into bulleted label/value
 * records. Literal `|` in a cell over-splits, so such blocks fall back to a
 * verbatim, lossless render through the wrap path. */

#define TBL_MAX_COLS 32
#define TBL_MAX_ROWS 2048
#define TBL_MAX_BYTES (1 << 16)

enum tbl_state { TBL_OFF = 0, TBL_HDR, TBL_DLM, TBL_BODY };

static void rd_feed_text(struct renderer *r, const char *s, size_t n);

/* Split a trimmed row into cell spans; optional border pipes are ignored.
 * `\|` is a literal pipe, not a cell separator. */
static int tbl_split_row(const char *s, size_t len, const char **cp, size_t *clen,
                         int max)
{
    size_t a = 0, b = len;
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r'))
        a++;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r'))
        b--;
    if (a < b && s[a] == '|')
        a++;
    if (b > a && s[b - 1] == '|' && !(b - 1 > a && s[b - 2] == '\\'))
        b--;
    int n = 0;
    size_t start = a;
    size_t i = a;
    while (i <= b) {
        if (i == b || s[i] == '|') {
            size_t ca = start, cb = i;
            while (ca < cb && (s[ca] == ' ' || s[ca] == '\t'))
                ca++;
            while (cb > ca && (s[cb - 1] == ' ' || s[cb - 1] == '\t'))
                cb--;
            if (n < max) {
                cp[n] = s + ca;
                clen[n] = cb - ca;
            }
            n++;
            start = i + 1;
            i++;
            continue;
        }
        if (s[i] == '\\' && i + 1 < b && s[i + 1] == '|') {
            i += 2;
            continue;
        }
        i++;
    }
    return n;
}

/* Number of `:?-+:?` delimiter cells, or 0. Colons are valid only at edges.
 * Models sometimes emit the dashes as box-drawing `─` (which Windows
 * Terminal renders narrow), so that form is accepted too. */
static int tbl_delim_cols(const char *s, size_t len)
{
    const char *cp[TBL_MAX_COLS];
    size_t cl[TBL_MAX_COLS];
    int n = tbl_split_row(s, len, cp, cl, TBL_MAX_COLS);
    if (n < 1 || n > TBL_MAX_COLS)
        return 0;
    for (int j = 0; j < n; j++) {
        const char *c = cp[j];
        size_t a = 0, b = cl[j];
        if (b == 0)
            return 0;
        if (c[a] == ':')
            a++;
        if (b > a && c[b - 1] == ':')
            b--;
        if (a >= b)
            return 0;
        for (size_t k = a; k < b;) {
            uint32_t dash;
            size_t dl = u8_step(c + k, b - k, &dash);
            if (dash != '-' && dash != 0x2500)
                return 0;
            k += dl;
        }
    }
    return n;
}

/* Emit the composed SGR for st whenever it differs from the last one. */
static void tbl_cell_sgr(struct buf *out, const struct inline_state *st,
                         char *last, int *have)
{
    if (!g_emit_vt)
        return;
    char seq[56];
    compose_sgr(seq, "", st);
    if (!*have || strcmp(seq, last) != 0) {
        buf_appends(out, seq);
        memcpy(last, seq, strlen(seq) + 1); /* last is the caller's char[56] */
        *have = 1;
    }
}

/* Render one cell's inline markers (**bold**, *em*, `code`, ~~strike~~) into
 * styled bytes. Full lookahead, cached: each codepoint is decoded exactly once
 * and slides into `cp` on the next iteration. next == 0 means "no byte after
 * this one", which the boundary checks rely on. */
static void tbl_cell_styled(struct buf *out, const char *s, size_t n, int bold_base)
{
    struct inline_state st = { 0, 0, 0, 0, 0 };
    char last[56];
    int have = 0;
    uint32_t prev = 0;
    size_t i = 0;
    if (bold_base)
        st.bold = 1; /* header cells: inner ** toggles are suppressed */
    uint32_t cp = 0, next = 0;
    size_t clen = 0, nlen = 0;
    if (n) {
        clen = u8_step(s, n, &cp);
        if (i + clen < n)
            nlen = u8_step(s + clen, n - clen, &next);
    }
    while (i < n) {
        size_t adv; /* bytes consumed from s this iteration */
        if (cp == '`') {
            st.code = !st.code;
            adv = clen;
        } else if (cp == 92) {
            /* backslash: escaped punctuation prints literally */
            if (nlen && rd_is_ascii_punct(next)) {
                tbl_cell_sgr(out, &st, last, &have);
                buf_append_cp(out, next);
                prev = next;
                adv = clen + nlen;
            } else {
                tbl_cell_sgr(out, &st, last, &have);
                buf_append_cp(out, cp);
                prev = cp;
                adv = clen;
            }
        } else if (cp == '~') {
            if (next == '~') {
                st.strike = !st.strike;
                adv = clen + nlen; /* ASCII pair: 1 + 1 */
            } else {
                tbl_cell_sgr(out, &st, last, &have);
                buf_append_cp(out, cp);
                prev = cp;
                adv = clen;
            }
        } else if (cp == '*' || cp == '_') {
            if (next == cp) {
                if (!bold_base)
                    st.bold = !st.bold;
                adv = clen + nlen;
            } else {
                int open_boundary = prev == 0 || cp_is_boundary(prev);
                int close_boundary = cp_is_boundary(next);
                int emit;
                if (st.italic) {
                    st.italic = 0;
                    emit = 0;
                } else if (cp == '*') {
                    emit = !open_boundary || (next && close_boundary);
                    if (!emit)
                        st.italic = 1;
                } else {
                    emit = !(open_boundary && next && !close_boundary);
                    if (!emit)
                        st.italic = 1;
                }
                if (emit) {
                    tbl_cell_sgr(out, &st, last, &have);
                    buf_append_cp(out, cp);
                    prev = cp;
                }
                adv = clen;
            }
        } else {
            tbl_cell_sgr(out, &st, last, &have);
            buf_append_cp(out, cp);
            prev = cp;
            adv = clen;
        }
        i += adv;
        /* slide the one-decode lookahead forward */
        if (adv > clen) { /* the lookahead was swallowed: reload both */
            if (i < n) {
                clen = u8_step(s + i, n - i, &cp);
                if (i + clen < n) {
                    nlen = u8_step(s + i + clen, n - i - clen, &next);
                } else {
                    nlen = 0;
                    next = 0;
                }
            }
        } else { /* cp moves up to the old lookahead */
            cp = next;
            clen = nlen;
            nlen = 0;
            next = 0;
            if (i < n && i + clen < n)
                nlen = u8_step(s + i + clen, n - i - clen, &next);
        }
    }
}

struct tbl_cell {
    struct buf bytes;
    int width;
};

static void tbl_cell_render(struct tbl_cell *c, const char *s, size_t n, int bold_base)
{
    memset(c, 0, sizeof *c);
    tbl_cell_styled(&c->bytes, s, n, bold_base);
    c->width = (int)visible_width(c->bytes.p, c->bytes.len);
}

static void tbl_sep_emit(struct buf *line)
{
    buf_appendc(line, ' ');
    buf_appends(line, vt_or("\x1b[2m│\x1b[0m", "|"));
    buf_appendc(line, ' ');
}

static void tbl_hline_emit(struct buf *line, int n)
{
    for (int i = 0; i < n; i++)
        buf_appends(line, vt_or("\x1b[2m─\x1b[0m", "-"));
}

/* Split an aligned cell's padding into left/right parts. */
static void tbl_pad(char align, int pad, int *padl, int *padr)
{
    *padl = align == 'R' ? pad : align == 'C' ? pad / 2 : 0;
    *padr = pad - *padl;
}

/* Flush buffered rows verbatim through the wrap path (lossless fallback). */
static void tbl_flush_verbatim(struct renderer *r)
{
    size_t i = 0;
    while (i < r->tbl_rows.len) {
        char *nl = memchr(r->tbl_rows.p + i, '\n', r->tbl_rows.len - i);
        size_t llen = (size_t)((nl ? nl : r->tbl_rows.p + r->tbl_rows.len)
                               - (r->tbl_rows.p + i));
        if (llen) {
            painter_paint_line(r->cur, r->tbl_rows.p + i, llen);
        } else {
            out_puts("\r\n");
            painter_close_row(r->cur);
        }
        i += llen + (nl ? 1 : 0);
    }
}

/* Replay held rows through the normal inline path (table refused). */
static void tbl_replay_normal(struct renderer *r)
{
    struct buf all = BUF_INIT;
    buf_append_n(&all, r->tbl_rows.p, r->tbl_rows.len);
    buf_append_n(&all, r->tbl_line.p, r->tbl_line.len);
    buf_appendc(&all, '\n');
    buf_reset(&r->tbl_rows);
    buf_reset(&r->tbl_line);
    r->tbl_state = TBL_OFF;
    r->tbl_replay = 1;
    rd_feed_text(r, all.p, all.len);
    r->tbl_replay = 0;
    buf_free(&all);
}

static void tbl_finalize(struct renderer *r)
{
    struct buf *tb = &r->tbl_rows;
    r->tbl_state = TBL_OFF;

    const char *ls[TBL_MAX_ROWS];
    size_t ll[TBL_MAX_ROWS];
    int lc = 0;
    size_t s0 = 0;
    for (size_t k = 0; k < tb->len && lc < TBL_MAX_ROWS; k++) {
        if (tb->p[k] == '\n') {
            ls[lc] = tb->p + s0;
            ll[lc] = k - s0;
            lc++;
            s0 = k + 1;
        }
    }
    if (lc >= TBL_MAX_ROWS && s0 < tb->len) {
        tbl_flush_verbatim(r);
        buf_reset(tb);
        return;
    }

    const char *hcp[TBL_MAX_COLS];
    size_t hcl[TBL_MAX_COLS];
    int ncols = lc >= 1 ? tbl_split_row(ls[0], ll[0], hcp, hcl, TBL_MAX_COLS) : 0;
    if (ncols > TBL_MAX_COLS)
        ncols = TBL_MAX_COLS;
    if (lc < 2 || ncols < 1) {
        tbl_flush_verbatim(r);
        buf_reset(tb);
        return;
    }

    /* A literal `|` in a cell over-splits (no escape parsing): never drop
     * the extra cells — fall back to the verbatim render. */
    for (int row = 2; row < lc; row++) {
        const char *bcp[TBL_MAX_COLS];
        size_t bcl[TBL_MAX_COLS];
        if (tbl_split_row(ls[row], ll[row], bcp, bcl, TBL_MAX_COLS) > ncols) {
            tbl_flush_verbatim(r);
            buf_reset(tb);
            return;
        }
    }

    const char *dcp[TBL_MAX_COLS];
    size_t dcl[TBL_MAX_COLS];
    int ndelim = tbl_split_row(ls[1], ll[1], dcp, dcl, TBL_MAX_COLS);
    char align[TBL_MAX_COLS];
    for (int j = 0; j < ncols; j++) {
        char a = 'L';
        if (j < ndelim && dcl[j] > 0) {
            int lcolon = dcp[j][0] == ':';
            int rcolon = dcp[j][dcl[j] - 1] == ':';
            a = (lcolon && rcolon) ? 'C' : rcolon ? 'R' : 'L';
        }
        align[j] = a;
    }

    int nbody = lc - 2;
    int nrows = 1 + nbody;
    struct tbl_cell *grid = xcalloc((size_t)nrows * ncols, sizeof *grid);
    for (int j = 0; j < ncols; j++)
        tbl_cell_render(&grid[j], hcp[j], hcl[j], 1);
    for (int row = 0; row < nbody; row++) {
        const char *bcp[TBL_MAX_COLS];
        size_t bcl[TBL_MAX_COLS];
        int got = tbl_split_row(ls[2 + row], ll[2 + row], bcp, bcl, TBL_MAX_COLS);
        for (int j = 0; j < ncols; j++) {
            struct tbl_cell *cell = &grid[(size_t)(1 + row) * ncols + j];
            if (j < got)
                tbl_cell_render(cell, bcp[j], bcl[j], 0);
            else
                tbl_cell_render(cell, "", 0, 0);
        }
    }

    int colw[TBL_MAX_COLS];
    int total = 0;
    for (int j = 0; j < ncols; j++) {
        int w = 1; /* keep an empty column visible */
        for (int row = 0; row < nrows; row++) {
            int cw = grid[(size_t)row * ncols + j].width;
            if (cw > w)
                w = cw;
        }
        colw[j] = w;
        total += w;
    }
    /* separator cost in the painter's own width units (" │ " with the
     * glyph counted wide under VT) so the fits-check matches append_styled */
    int sepw = 2 + (g_emit_vt ? u8_cp_width(0x2502) : 1);
    total += (ncols - 1) * sepw;

    int limit = r->cur->usable;
    if (total > limit && nbody > 0) {
        /* Reflow into bulleted label/value records that wrap at any width. */
        for (int row = 0; row < nbody; row++) {
            for (int j = 0; j < ncols; j++) {
                struct buf line = BUF_INIT;
                buf_appends(&line, j == 0 ? vt_or("\x1b[2m•\x1b[0m ", "• ") : "  ");
                buf_appends(&line, vt_or("\x1b[1m", ""));
                buf_append_n(&line, grid[j].bytes.p, grid[j].bytes.len);
                buf_appends(&line, vt_or("\x1b[0m", ""));
                buf_appends(&line, ": ");
                struct tbl_cell *val = &grid[(size_t)(1 + row) * ncols + j];
                buf_append_n(&line, val->bytes.p, val->bytes.len);
                painter_paint_line(r->cur, line.p, line.len);
                buf_free(&line);
            }
        }
    } else {
        /* Aligned grid: bold header, dim rule with ┼ under each │, body. */
        struct buf line = BUF_INIT;
        for (int j = 0; j < ncols; j++) {
            struct tbl_cell *c = &grid[j];
            int padl, padr;
            tbl_pad(align[j], colw[j] - c->width, &padl, &padr);
            if (padl > 0)
                buf_append_spaces(&line, (size_t)padl);
            buf_appends(&line, vt_or("\x1b[1m", ""));
            buf_append_n(&line, c->bytes.p, c->bytes.len);
            buf_appends(&line, vt_or("\x1b[0m", ""));
            if (j < ncols - 1) {
                if (padr > 0)
                    buf_append_spaces(&line, (size_t)padr);
                tbl_sep_emit(&line);
            }
        }
        painter_paint_line(r->cur, line.p, line.len);
        buf_reset(&line);
        buf_appends(&line, vt_or("\x1b[2m", ""));
        for (int j = 0; j < ncols; j++) {
            tbl_hline_emit(&line, colw[j]);
            if (j < ncols - 1)
                buf_appends(&line, vt_or("\x1b[2m─┼─\x1b[0m", "-+-"));
        }
        buf_appends(&line, vt_or("\x1b[0m", ""));
        painter_paint_line(r->cur, line.p, line.len);
        buf_reset(&line);
        for (int row = 0; row < nbody; row++) {
            for (int j = 0; j < ncols; j++) {
                struct tbl_cell *c =
                    &grid[(size_t)(1 + row) * ncols + j];
                int padl, padr;
                tbl_pad(align[j], colw[j] - c->width, &padl, &padr);
                if (padl > 0)
                    buf_append_spaces(&line, (size_t)padl);
                buf_append_n(&line, c->bytes.p, c->bytes.len);
                if (j < ncols - 1) {
                    if (padr > 0)
                        buf_append_spaces(&line, (size_t)padr);
                    tbl_sep_emit(&line);
                }
            }
            painter_paint_line(r->cur, line.p, line.len);
            buf_reset(&line);
        }
        buf_free(&line);
    }

    for (int row = 0; row < nrows; row++)
        for (int j = 0; j < ncols; j++)
            buf_free(&grid[(size_t)row * ncols + j].bytes);
    free(grid);
    buf_reset(tb);
}

/* Feed one codepoint while a table is being collected. */
static void rd_tbl_char(struct renderer *r, uint32_t c)
{
    if (c == '\r')
        return; /* CRLF handled at \n */
    if (c != '\n') {
        if (r->tbl_line.len + r->tbl_rows.len < TBL_MAX_BYTES)
            buf_append_cp(&r->tbl_line, c);
        else {
            /* oversized row: bail the block to verbatim and go literal */
            tbl_flush_verbatim(r);
            buf_reset(&r->tbl_rows);
            buf_reset(&r->tbl_line);
            r->tbl_state = TBL_OFF;
            r->line_start = 0;
            rd_feed_char(r, c);
        }
        return;
    }

    size_t llen = r->tbl_line.len;
    int blank = 1, pipe = 0;
    for (size_t k = 0; k < llen; k++) {
        char ch = r->tbl_line.p[k];
        if (ch != ' ' && ch != '\t')
            blank = 0;
        if (ch == '|')
            pipe = 1;
    }

    if (r->tbl_state == TBL_HDR) {
        buf_append_n(&r->tbl_rows, r->tbl_line.p, llen);
        buf_appendc(&r->tbl_rows, '\n');
        r->tbl_state = TBL_DLM; /* hold until the next row proves the table */
    } else if (r->tbl_state == TBL_DLM) {
        int hcols = tbl_split_row(r->tbl_rows.p, r->tbl_rows.len - 1, NULL,
                                  NULL, 0);
        int dcols = pipe ? tbl_delim_cols(r->tbl_line.p, llen) : 0;
        if (dcols >= 1 && dcols == hcols && hcols >= 1 && hcols <= TBL_MAX_COLS) {
            buf_append_n(&r->tbl_rows, r->tbl_line.p, llen);
            buf_appendc(&r->tbl_rows, '\n');
            r->tbl_state = TBL_BODY;
        } else {
            tbl_replay_normal(r); /* not a table: both rows stay literal */
            return;               /* replay consumed the trailing newline */
        }
    } else { /* TBL_BODY */
        if (blank || !pipe || r->tbl_rows.len + llen + 1 > TBL_MAX_BYTES) {
            tbl_finalize(r);
            /* the terminating row re-enters the normal path */
            buf_appendc(&r->tbl_line, '\n');
            rd_feed_text(r, r->tbl_line.p, r->tbl_line.len);
        } else {
            buf_append_n(&r->tbl_rows, r->tbl_line.p, llen);
            buf_appendc(&r->tbl_rows, '\n');
        }
    }
    buf_reset(&r->tbl_line);
}

/* Collect c into the probe buffer (still probing). */
static int probe_more(struct renderer *r, uint32_t c)
{
    buf_append_cp(&r->probe, c);
    r->probe_cp++;
    return 1;
}

/* The probe is not a block marker: flush it through the inline path.
 * Leaves line_start alone — following codepoints may still probe. */
static int probe_inline(struct renderer *r, uint32_t c)
{
    rd_probe_flush(r);
    rd_feed_char(r, c);
    return 1;
}

/* Common tail of both list markers: consume the separator space, start
 * the task-list scan, indent wrapped rows to the content column. */
static void probe_list_start(struct renderer *r, int indent)
{
    rd_feed_char(r, (uint32_t)' ');
    r->task_scan = 1;
    r->task_n = 0;
    r->text_p.row_indent = r->probe_indent + indent;
}

/* Probe one codepoint at line start. Returns 1 when consumed (still probing
 * or a block decision consumed it), 0 when the probe ended and c belongs to
 * the inline path. */
static int rd_probe_char(struct renderer *r, uint32_t c)
{
    size_t n = r->probe_cp;

    if (n == 0 && c == ' ') {
        r->probe_indent++; /* keep probing: indent feeds nested lists */
        return 1;
    }
    if (n == 0 && (c == '`' || c == '~'))
        return probe_more(r, c);
    if (n > 0 && (r->probe.p[0] == '`' || r->probe.p[0] == '~')) {
        if (c == (uint32_t)r->probe.p[0] && r->probe_cp < 16)
            return probe_more(r, c);
        if (r->probe_cp >= 3) {
            /* fence opens; what follows is the language tag (or newline) */
            r->fence = 1;
            r->fence_marker = r->probe.p[0];
            r->fence_run = (int)r->probe_cp;
            r->fence_lang.len = 0;
            r->line_start = 0;
            r->probe.len = 0;
            r->probe_cp = 0;
            if (c != '\r')
                rd_fence_char(r, c); /* header on \n, else first lang char */
            return 1;
        }
        /* 1-2 backticks then something else: inline code span */
        return probe_inline(r, c);
    }
    if (n == 0 && c == '#')
        return probe_more(r, c);
    if (n > 0 && r->probe.p[0] == '#') {
        if (c == '#' && r->probe_cp < 6)
            return probe_more(r, c);
        if (c == ' ' || c == '\t') {
            /* heading: level = probe_cp */
            r->text_st.bold = 1;
            r->text_st.under = 1;
            r->cur->have_sgr = 0;
            r->line_start = 0;
            r->probe.len = 0;
            r->probe_cp = 0;
            return 1;
        }
        /* "#tag": not a heading */
        return probe_inline(r, c);
    }
    if (n == 0 && (c == '-' || c == '*' || c == '_' || c == '>'))
        return probe_more(r, c);
    if (n == 0 && c >= '0' && c <= '9')
        return probe_more(r, c);
    if (n > 0 && r->probe.p[0] == '>') {
        /* '>', '> ' and '>text' all open the quote; the separator space
         * is consumed, everything else goes to the inline path */
        painter_set_prefix(&r->text_p, vt_or(PREFIX_QUOTE, "│ "));
        r->line_start = 0;
        r->probe.len = 0;
        r->probe_cp = 0;
        if (c == ' ' || c == '\t')
            return 1;
        rd_feed_char(r, c);
        return 1;
    }
    if (n > 0 && (r->probe.p[0] == '-' || r->probe.p[0] == '_'
                  || r->probe.p[0] == '*')) {
        uint32_t m = (uint32_t)r->probe.p[0];
        if (c == m && r->probe_cp < 8)
            return probe_more(r, c);
        if (r->probe_cp >= 3 && (c == ' ' || c == '\t' || c == '\r' || c == '\n'
                                 || cp_is_boundary(c))) {
            r->probe.len = 0;
            r->probe_cp = 0;
            r->line_start = 0;
            rd_emit_hr(r);
            if (c == '\n' || c == '\r')
                rd_line_reset(r);
            return 1;
        }
        if ((m == '-' || m == '*') && c == ' ') {
            /* bullet */
            r->line_start = 0;
            r->probe.len = 0;
            r->probe_cp = 0;
            struct painter *p = r->cur;
            painter_ensure_row(p);
            painter_emit_sgr(p, &p->pending);
            buf_appends(&p->pending, vt_or("\x1b[36m•\x1b[0m", "•"));
            p->pending_width += 2; /* • is ambiguous-wide */
            probe_list_start(r, 2);
            return 1;
        }
        /* not a marker: flush to inline */
        return probe_inline(r, c);
    }
    if (n > 0 && r->probe.p[0] >= '0' && r->probe.p[0] <= '9') {
        if (c >= '0' && c <= '9')
            return probe_more(r, c);
        if (c == '.')
            return probe_more(r, c);
        if (c == ' ' && r->probe.len > 0
            && r->probe.p[r->probe.len - 1] == '.') {
            /* ordered list item */
            r->line_start = 0;
            struct painter *p = r->cur;
            painter_ensure_row(p);
            painter_emit_sgr(p, &p->pending);
            if (g_emit_vt)
                buf_appends(&p->pending, "\x1b[36m");
            buf_append_n(&p->pending, r->probe.p, r->probe.len);
            if (g_emit_vt)
                buf_appends(&p->pending, "\x1b[0m");
            p->pending_width += r->probe_cp;
            r->probe.len = 0;
            r->probe_cp = 0;
            probe_list_start(r, 3);
            return 1;
        }
        /* plain number */
        return probe_inline(r, c);
    }
    /* probe holds something undecided that c cannot extend: flush */
    if (n == 0 && c == '|' && !r->tbl_replay) {
        /* possible table header: hold until the next row proves it */
        r->tbl_state = TBL_HDR;
        buf_append_cp(&r->tbl_line, c);
        return 1;
    }
    r->line_start = 0;
    return probe_inline(r, c);
}

static void rd_line_reset(struct renderer *r)
{
    r->text_p.row_indent = 0;
    painter_set_prefix(&r->text_p, NULL);
    r->text_st.bold = r->text_st.italic = r->text_st.strike = 0;
    r->text_st.code = r->text_st.under = 0;
    r->cur->have_sgr = 0;
    r->hold = 0;
    r->task_scan = 0;
    r->task_n = 0;
    r->line_start = 1;
    r->probe.len = 0;
    r->probe_cp = 0;
    r->probe_indent = 0;
}

static void rd_finish_line(struct renderer *r)
{
    /* resolve a pending marker at line end, then end the row */
    if (r->hold)
        rd_resolve_hold(r, 0);
    if (painter_row_has_content(r->cur)) {
        painter_commit_row(r->cur);
    } else {
        /* an empty markdown line: erase the row first — the trailing
         * composer draw may have painted it — then newline */
        out_puts(g_emit_vt ? "\r\x1b[0K\r\n" : "\r\n");
        painter_close_row(r->cur);
    }
    r->text_p.row_indent = 0;
    painter_set_prefix(&r->text_p, NULL);
}

/* --- channel management and public entry points -------------------------- */

static void renderer_set_channel(struct renderer *r, enum channel ch)
{
    if (r->channel == ch)
        return;
    if (r->channel == CH_TEXT) {
        if (r->tbl_state != TBL_OFF) {
            if (r->tbl_state == TBL_BODY)
                tbl_finalize(r);
            else
                tbl_replay_normal(r);
        } else if (r->line_start && !r->cur->row_open) {
            /* trailing newline already closed the row: nothing to finish */
        } else {
            if (r->hold)
                rd_resolve_hold(r, 0);
            if (r->fence)
                rd_fence_close(r);
            rd_finish_line(r);
        }
        r->probe.len = 0;
        r->probe_cp = 0;
        r->line_start = 1;
    } else if (r->channel == CH_THINK) {
        if (painter_row_has_content(&r->think_p))
            painter_commit_row(&r->think_p);
        else
            painter_close_row(&r->think_p);
    }
    r->channel = ch;
    r->cur = ch == CH_THINK ? &r->think_p : &r->text_p;
    painter_close_row(r->cur);
    if (ch == CH_TEXT)
        r->line_start = 1;
}

static void renderer_think(struct renderer *r, const char *s, size_t n)
{
    renderer_set_channel(r, CH_THINK);
    painter_feed_plain(&r->think_p, s, n);
}

static void renderer_text(struct renderer *r, const char *s, size_t n)
{
    renderer_set_channel(r, CH_TEXT);
    rd_feed_text(r, s, n);
    painter_screen_throttled(r->cur); /* one frame per delta batch */
}

/* Feed text codepoints through fence/table/block handling. During a replay
 * of refused table lines the tbl_replay flag keeps the probe from entering
 * table collection again. */
static void rd_feed_text(struct renderer *r, const char *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        uint32_t cp;
        size_t clen = u8_step(s + i, n - i, &cp);
        i += clen;
        if (r->fence) {
            rd_fence_char(r, cp);
            continue;
        }
        if (r->tbl_state) {
            rd_tbl_char(r, cp);
            continue;
        }
        if (cp == '\n' || cp == '\r') {
            if (cp == '\r')
                continue; /* CRLF handled at \n */
            if (r->task_scan)
                rd_task_flush(r);
            if (r->hold)
                rd_resolve_hold(r, 0);
            rd_finish_line(r);
            rd_line_reset(r);
            continue;
        }
        if (r->line_start) {
            if (rd_probe_char(r, cp))
                continue;
        }
        /* fast path: a run of codepoints with no marker meaning — printable
         * ASCII and whole multi-byte characters — goes to the painter in
         * one call instead of per codepoint. The run breaks exactly where
         * the marker state machine would, so behavior is identical. */
        if (!r->hold && !r->task_scan && rd_plain_cp(cp)) {
            size_t start = i - clen;
            size_t run = i;
            while (run < n) {
                unsigned char b = (unsigned char)s[run];
                if (b < 0x20 || b == 0x7F)
                    break;
                if (b < 0x80 && (b == '*' || b == '_' || b == '`' || b == '~'
                                 || b == '\\'))
                    break;
                run++;
            }
            painter_append_styled(r->cur, s + start, run - start);
            size_t last = u8_prev(s, run); /* boundary decisions use it */
            u8_decode(s + last, run - last, &cp);
            r->prev_c = (int)cp;
            i = run;
            continue;
        }
        rd_feed_char(r, cp);
    }
}

static void renderer_end_turn(struct renderer *r)
{
    if (r->channel == CH_NONE)
        return;
    if (r->channel == CH_TEXT) {
        if (r->fence)
            rd_fence_close(r);
        if (r->tbl_state != TBL_OFF) {
            if (r->tbl_state == TBL_BODY)
                tbl_finalize(r);
            else
                tbl_replay_normal(r);
            /* both paths end on committed rows: nothing left to finish */
        } else if (r->line_start && !r->cur->row_open) {
            /* the model's trailing newline already closed the row —
             * finishing again would print a stray blank line */
        } else {
            rd_finish_line(r);
        }
    } else if (r->cur->row_open) {
        rd_finish_line(r);
    }
    r->channel = CH_NONE;
    r->probe.len = 0;
    r->probe_cp = 0;
    r->line_start = 1;
    r->text_p.row_indent = 0;
    painter_set_prefix(&r->text_p, NULL);
}

/* Streaming renderer wired to the protocol hooks. */
static struct renderer g_renderer;

static void hook_think(const char *s, size_t n)
{
    InterlockedExchange(&g_busy, 2);
    g_stream_bytes += (unsigned long long)n;
    renderer_think(&g_renderer, s, n);
}

static void hook_text(const char *s, size_t n)
{
    InterlockedExchange(&g_busy, 2);
    g_stream_bytes += (unsigned long long)n;
    renderer_text(&g_renderer, s, n);
}

/* ==========================================================================
 * 6. protocol — SSE framing + OpenAI chat-completions deltas
 * ========================================================================== */

/* --- SSE framing: stateful across transport chunks --------------------- */

typedef void (*sse_data_cb)(struct str data, void *user);

struct sse_parser {
    struct buf line;   /* partial line carried across transport chunks */
    struct buf data;   /* data: lines of the current event, \n-joined */
    struct str direct; /* first data line of the event, while it still points
                        * into the transport chunk: zero-copy until a second
                        * data line joins it or the chunk ends */
    int have_data;
};

static void sse_parser_free(struct sse_parser *sp)
{
    buf_free(&sp->line);
    buf_free(&sp->data);
}

static void sse_dispatch(struct sse_parser *sp, sse_data_cb cb, void *user)
{
    if (sp->have_data) {
        struct str d = sp->direct.n ? sp->direct
                                    : (struct str){ sp->data.p, sp->data.len };
        if (d.n)
            cb(d, user);
    }
    sp->data.len = 0;
    sp->direct.n = 0;
    sp->have_data = 0;
}

/* Fold one data payload into the event under assembly. A payload that lives
 * in the transport chunk (from_carry == 0) rides as a slice; joining a second
 * line — or the chunk ending — materializes it into sp->data. */
static void sse_data_add(struct sse_parser *sp, const char *d, size_t dn,
                         int from_carry)
{
    if (!sp->have_data) {
        sp->have_data = 1;
        if (!from_carry) {
            sp->direct.p = d;
            sp->direct.n = dn;
        } else {
            buf_append_n(&sp->data, d, dn);
        }
        return;
    }
    if (sp->direct.n) {
        buf_append_n(&sp->data, sp->direct.p, sp->direct.n);
        sp->direct.n = 0;
    }
    if (sp->data.len > 0)
        buf_appendc(&sp->data, '\n');
    buf_append_n(&sp->data, d, dn);
}

/* Feed raw transport bytes; complete events arrive through cb. Lines are
 * gathered with memchr in one pass — no per-byte buffer appends. A line whole
 * inside the chunk is parsed where it lies; only a line split across two
 * chunks is copied into sp->line, and only a multi-line event accumulates in
 * sp->data, so the common OpenAI event costs zero copies between the socket
 * and the delta scanner. */
static void sse_feed(struct sse_parser *sp, const char *bytes, size_t n,
                     sse_data_cb cb, void *user)
{
    size_t i = 0;
    while (i < n) {
        const char *nl = memchr(bytes + i, '\n', n - i);
        size_t take = nl ? (size_t)(nl - (bytes + i)) : n - i;
        if (!nl) {
            /* no line end in the rest of the chunk: carry the tail */
            buf_append_n(&sp->line, bytes + i, take);
            break;
        }
        struct str line;
        int from_carry;
        if (sp->line.len) {
            /* a line split across chunks: finish it in the carry buffer */
            buf_append_n(&sp->line, bytes + i, take);
            line.p = sp->line.p;
            line.n = sp->line.len;
            from_carry = 1;
        } else {
            line.p = bytes + i; /* whole line here: parse it in place */
            line.n = take;
            from_carry = 0;
        }
        i += take + 1; /* consume the newline */
        if (line.n > 0 && line.p[line.n - 1] == '\r')
            line.n--;
        if (line.n == 0) {
            sse_dispatch(sp, cb, user);
        } else if (line.n > 6 && memcmp(line.p, "data:", 5) == 0) {
            const char *d = line.p + 5;
            size_t dn = line.n - 5;
            if (*d == ' ') {
                d++;
                dn--;
            }
            sse_data_add(sp, d, dn, from_carry);
        }
        /* event:, id:, retry:, comments: ignored — OpenAI deltas carry all
         * state in data lines */
        sp->line.len = 0;
    }
    /* a payload still pointing into this chunk cannot outlive the call */
    if (sp->direct.n) {
        buf_append_n(&sp->data, sp->direct.p, sp->direct.n);
        sp->direct.n = 0;
    }
}

/* --- stream state: three delta channels + tool call assembly ---------- */

enum finish_kind {
    FINISH_NONE = 0,
    FINISH_STOP,
    FINISH_TOOL_CALLS,
    FINISH_LENGTH,
    FINISH_ERROR,
};

struct stream_call {
    size_t index;
    char *id;         /* heap, set once when first seen */
    char *name;       /* heap, first chunk carries it */
    struct buf args;  /* arguments fragments appended in order */
};

struct stream_hooks {
    void (*think)(const char *s, size_t n);
    void (*text)(const char *s, size_t n);
};

struct stream_state {
    struct buf content;    /* full assistant text (owned) */
    struct buf reasoning;  /* full reasoning text (owned) */
    struct stream_call *calls;
    size_t n_calls, cap_calls;
    enum finish_kind finish;
    int64_t prompt_tokens, completion_tokens;
    int64_t cache_tokens; /* cached prompt tokens, when the API reports it */
    int has_cache;
    int got_usage;
    size_t request_bytes; /* serialized request size, for the no-usage
                           * compaction estimate */
    size_t request_shared; /* leading bytes identical to this process's
                            * previous request: the prefix-cache diagnostic */
    int request_prev;      /* 0 on the first round, where there is nothing
                            * to compare against */
    char *error; /* heap; set when the API reported an error */
    int looped;     /* output collapsed into repetition: the stream aborts */
    size_t loop_next; /* content length at which the next scan is due */
};

static void stream_state_init(struct stream_state *st)
{
    memset(st, 0, sizeof *st);
}

static void stream_state_free(struct stream_state *st)
{
    buf_free(&st->content);
    buf_free(&st->reasoning);
    for (size_t i = 0; i < st->n_calls; i++) {
        free(st->calls[i].id);
        free(st->calls[i].name);
        buf_free(&st->calls[i].args);
    }
    free(st->calls);
    free(st->error);
    memset(st, 0, sizeof *st);
}

static struct stream_call *stream_call_by_index(struct stream_state *st,
                                                size_t idx)
{
    for (size_t i = 0; i < st->n_calls; i++)
        if (st->calls[i].index == idx)
            return &st->calls[i];
    if (st->n_calls == st->cap_calls) {
        st->cap_calls = st->cap_calls ? st->cap_calls * 2 : 4;
        st->calls = xrealloc(st->calls, st->cap_calls * sizeof *st->calls);
    }
    struct stream_call *c = &st->calls[st->n_calls++];
    memset(c, 0, sizeof *c);
    c->index = idx;
    return c;
}

struct chat_request {
    struct stream_state *st;
    struct stream_hooks hooks;
    struct sse_parser sse;
    struct arena arena;   /* reused per event */
};

/* --- the delta fast scan -------------------------------------------------- */
/* An SSE delta is a fixed envelope, and paying a DOM for it is the most
 * expensive thing kk does per streamed byte: on a 21,627-event, 4.4MB stream
 * the tree cost 878 ns/event (222 MB/s) against 5.7 GB/s for the framing —
 * 90% of the protocol path. About 21 arena nodes exist only so jobj_get can
 * reach "content".
 *
 * The scan below walks the envelope by index and allocates nothing: the keys
 * the stream uses become slices into the caller's buffer, every other member
 * is skipped structurally. Wherever it is not certain — an unexpected value
 * type, an "error" member, a populated "usage", more than FAST_CALLS calls in
 * one event, malformed bytes — it returns 0 and the general parser handles
 * the event. The DOM path stays the definition of the protocol; the fast
 * scan only ever has to match it. Both feed the same three appliers below,
 * so nothing is implemented twice. */
#define FAST_CALLS 4

struct call_delta {
    int64_t index;
    int has_index;  /* the member existed: the DOM reads a null index as 0 */
    int id_key, name_key, args_key; /* the key appeared: jobj_get stops at the
                                     * first one, whatever it holds */
    struct str id, name, args; /* still-escaped slices, n == 0 when absent */
};

struct delta_hit {
    struct str content, reasoning, reasoning_alt;
    int content_key;       /* "content" appeared (jobj_get stops at the first) */
    int content_ok;        /* ... and it was a string */
    int saw_reasoning;     /* "reasoning_content" existed, any type: the DOM */
    int saw_reasoning_alt; /* checks it first and stops there */
    int finish_key;
    int finish_ok;         /* finish_reason was a string (possibly empty) */
    struct str finish;
    struct call_delta calls[FAST_CALLS];
    int n_calls;
};

/* A string literal at s[i] (which must be the opening quote): the slice
 * between the quotes and the index past the closing one, or (size_t)-1.
 * Delegates to jstr_end, so the escape rules are literally the parser's. */
static size_t jw_str(const char *s, size_t n, size_t i, struct str *out)
{
    if (i >= n || s[i] != '"')
        return (size_t)-1;
    return jstr_end(s, n, i + 1, out);
}

/* A number literal, converted exactly as jparse_number does. */
static int jw_num(const char *s, size_t n, size_t i, int64_t *out,
                  size_t *after)
{
    int is_int;
    size_t start = i;
    i = num_span(s, n, i, &is_int);
    if (i == start)
        return 0;
    num_convert(s + start, i - start, is_int, out);
    *after = i;
    return 1;
}

/* Consume any value, building nothing. (size_t)-1 when the bytes are not a
 * value at all. */
static size_t jw_value(const char *s, size_t n, size_t i, int depth)
{
    if (depth > JSON_MAX_DEPTH)
        return (size_t)-1;
    i = jw(s, n, i);
    if (i >= n)
        return (size_t)-1;
    char c = s[i];
    if (c == '"')
        return jw_str(s, n, i, NULL);
    if (c != '{' && c != '[') {
        size_t start = i;
        while (i < n) {
            char d = s[i];
            if (d == ',' || d == '}' || d == ']' || d == ':' || d <= ' ')
                break;
            i++;
        }
        return i == start ? (size_t)-1 : i;
    }
    char close = c == '{' ? '}' : ']';
    i = jw(s, n, i + 1);
    if (i < n && s[i] == close)
        return i + 1;
    for (;;) {
        if (c == '{') {
            i = jw_str(s, n, i, NULL);
            if (i == (size_t)-1)
                return (size_t)-1;
            i = jw(s, n, i);
            if (i >= n || s[i] != ':')
                return (size_t)-1;
            i = jw(s, n, i + 1);
        }
        i = jw_value(s, n, i, depth + 1);
        if (i == (size_t)-1)
            return (size_t)-1;
        i = jw(s, n, i);
        if (i < n && s[i] == ',') {
            i = jw(s, n, i + 1);
            continue;
        }
        if (i < n && s[i] == close)
            return i + 1;
        return (size_t)-1;
    }
}

/* One member of the object whose value position is *pi: the key and the index
 * of its value. 0 = a member was read, 1 = the object ended, -1 = garbage.
 * Four levels of the scan share this, so the separator bookkeeping is
 * written once. */
static int jw_member(const char *s, size_t n, size_t *pi, struct str *key)
{
    size_t i = jw(s, n, *pi);
    if (i < n && s[i] == '}') {
        *pi = i + 1;
        return 1;
    }
    i = jw_str(s, n, i, key);
    if (i == (size_t)-1)
        return -1;
    i = jw(s, n, i);
    if (i >= n || s[i] != ':')
        return -1;
    *pi = jw(s, n, i + 1);
    if (*pi >= n) /* a member with no value left in the buffer is not JSON;
                   * guarding here keeps every caller's s[i] in bounds */
        return -1;
    return 0;
}

/* The separator after a member or element: , or the closing brace/bracket.
 * 1 = more follow, 0 = container ended, -1 = garbage. */
static int jw_after(const char *s, size_t n, size_t *pi, char close)
{
    size_t i = jw(s, n, *pi);
    if (i < n && s[i] == ',') {
        *pi = jw(s, n, i + 1);
        return 1;
    }
    if (i < n && s[i] == close) {
        *pi = i + 1;
        return 0;
    }
    return -1;
}

#define JKEY(k, lit)                                                     \
    ((k).n == sizeof(lit) - 1 && memcmp((k).p, lit, sizeof(lit) - 1) == 0)

static int jw_is_null(const char *s, size_t n, size_t i)
{
    return i + 4 <= n && memcmp(s + i, "null", 4) == 0;
}

/* "tool_calls": [ {...}, ... ] — up to FAST_CALLS items, each read the way
 * the DOM loop reads one: the first key wins, a non-object element is skipped,
 * anything richer than that falls back rather than growing storage here. */
static size_t scan_tool_calls(const char *s, size_t n, size_t i,
                              struct delta_hit *h)
{
    i = jw(s, n, i);
    if (i >= n)
        return (size_t)-1;
    if (s[i] != '[')
        return jw_value(s, n, i, 1); /* no array: the DOM finds no calls */
    i = jw(s, n, i + 1);
    if (i < n && s[i] == ']')
        return i + 1;
    for (;;) {
        size_t j = jw(s, n, i);
        if (j >= n)
            return (size_t)-1;
        if (s[j] == '{') {
            struct call_delta *d = &h->calls[h->n_calls];
            memset(d, 0, sizeof *d);
            j = jw(s, n, j + 1);
            struct str key;
            for (;;) {
                int m = jw_member(s, n, &j, &key);
                if (m < 0)
                    return (size_t)-1;
                if (m == 1)
                    break;
                if (JKEY(key, "index")) {
                    if (!d->has_index) {
                        d->has_index = 1;
                        if (s[j] == '-' || (s[j] >= '0' && s[j] <= '9')) {
                            if (!jw_num(s, n, j, &d->index, &j))
                                return (size_t)-1;
                        } else {
                            /* any other value reads as index 0 in the DOM */
                            j = jw_value(s, n, j, 1);
                            if (j == (size_t)-1)
                                return (size_t)-1;
                        }
                    } else {
                        j = jw_value(s, n, j, 1);
                        if (j == (size_t)-1)
                            return (size_t)-1;
                    }
                } else if (JKEY(key, "id")) {
                    if (!d->id_key && s[j] == '"') {
                        d->id_key = 1;
                        j = jw_str(s, n, j, &d->id);
                        if (j == (size_t)-1)
                            return (size_t)-1;
                    } else {
                        j = jw_value(s, n, j, 1);
                        if (j == (size_t)-1)
                            return (size_t)-1;
                    }
                } else if (JKEY(key, "function")) {
                    size_t f = jw(s, n, j);
                    if (f >= n || s[f] != '{') {
                        j = jw_value(s, n, j, 1);
                        if (j == (size_t)-1)
                            return (size_t)-1;
                    } else {
                        j = jw(s, n, f + 1);
                        struct str fk;
                        for (;;) {
                            int fm = jw_member(s, n, &j, &fk);
                            if (fm < 0)
                                return (size_t)-1;
                            if (fm == 1)
                                break;
                            if (!d->name_key && JKEY(fk, "name")
                                && s[j] == '"') {
                                d->name_key = 1;
                                j = jw_str(s, n, j, &d->name);
                            } else if (!d->args_key && JKEY(fk, "arguments")
                                       && s[j] == '"') {
                                d->args_key = 1;
                                j = jw_str(s, n, j, &d->args);
                            } else {
                                j = jw_value(s, n, j, 1);
                            }
                            if (j == (size_t)-1)
                                return (size_t)-1;
                            int fs = jw_after(s, n, &j, '}');
                            if (fs < 0)
                                return (size_t)-1;
                            if (fs == 0)
                                break;
                        }
                    }
                } else {
                    j = jw_value(s, n, j, 1);
                    if (j == (size_t)-1)
                        return (size_t)-1;
                }
                int sep = jw_after(s, n, &j, '}');
                if (sep < 0)
                    return (size_t)-1;
                if (sep == 0)
                    break;
            }
            i = j;
            h->n_calls++;
        } else {
            /* a non-object element: the DOM skips it, so nothing is captured */
            i = jw_value(s, n, j, 1);
            if (i == (size_t)-1)
                return (size_t)-1;
        }
        int sep = jw_after(s, n, &i, ']');
        if (sep < 0)
            return (size_t)-1;
        if (sep == 0)
            return i;
        if (h->n_calls == FAST_CALLS)
            return (size_t)-1; /* more calls than this scan holds: the parser
                               * has no limit, so let it have the event */
    }
}

static size_t scan_delta(const char *s, size_t n, size_t i,
                         struct delta_hit *h)
{
    i = jw(s, n, i);
    if (i >= n)
        return (size_t)-1;
    if (s[i] != '{')
        return jw_value(s, n, i, 1);
    i = jw(s, n, i + 1);
    struct str key;
    for (;;) {
        int m = jw_member(s, n, &i, &key);
        if (m == 1)
            return i;
        if (m < 0)
            return (size_t)-1;
        if (JKEY(key, "content")) {
            if (!h->content_key && s[i] == '"') {
                h->content_key = 1;
                i = jw_str(s, n, i, &h->content);
                if (i == (size_t)-1)
                    return (size_t)-1;
                h->content_ok = 1;
            } else {
                i = jw_value(s, n, i, 1);
            }
        } else if (JKEY(key, "reasoning_content")) {
            if (!h->saw_reasoning && s[i] == '"') {
                i = jw_str(s, n, i, &h->reasoning);
                if (i == (size_t)-1)
                    return (size_t)-1;
            } else {
                i = jw_value(s, n, i, 1);
            }
            h->saw_reasoning = 1; /* the DOM stops looking once the key
                                   * exists, whatever it holds */
        } else if (JKEY(key, "reasoning")) {
            if (!h->saw_reasoning_alt && s[i] == '"') {
                i = jw_str(s, n, i, &h->reasoning_alt);
                if (i == (size_t)-1)
                    return (size_t)-1;
            } else {
                i = jw_value(s, n, i, 1);
            }
            h->saw_reasoning_alt = 1;
        } else if (JKEY(key, "tool_calls")) {
            i = scan_tool_calls(s, n, i, h);
        } else {
            i = jw_value(s, n, i, 1);
        }
        if (i == (size_t)-1)
            return (size_t)-1;
        int sep = jw_after(s, n, &i, '}');
        if (sep < 0)
            return (size_t)-1;
        if (sep == 0)
            return i;
    }
}

/* choices[0]: the DOM reads only the first element, so the rest is skipped
 * rather than parsed. */
static size_t scan_choice(const char *s, size_t n, size_t i,
                          struct delta_hit *h)
{
    i = jw(s, n, i);
    if (i >= n)
        return (size_t)-1;
    if (s[i] != '[')
        return jw_value(s, n, i, 1);
    i = jw(s, n, i + 1);
    if (i < n && s[i] == ']')
        return i + 1;
    if (s[i] != '{') {
        i = jw_value(s, n, i, 1); /* not an object: the DOM gets nothing */
        if (i == (size_t)-1)
            return (size_t)-1;
    } else {
        i = jw(s, n, i + 1);
        struct str key;
        for (;;) {
            int m = jw_member(s, n, &i, &key);
            if (m < 0)
                return (size_t)-1;
            if (m == 1)
                break;
            if (JKEY(key, "delta")) {
                i = scan_delta(s, n, i, h);
            } else if (JKEY(key, "finish_reason")) {
                if (!h->finish_key && s[i] == '"') {
                    h->finish_key = 1;
                    i = jw_str(s, n, i, &h->finish);
                    if (i == (size_t)-1)
                        return (size_t)-1;
                    h->finish_ok = 1;
                } else {
                    i = jw_value(s, n, i, 1);
                }
            } else {
                i = jw_value(s, n, i, 1);
            }
            if (i == (size_t)-1)
                return (size_t)-1;
            int sep = jw_after(s, n, &i, '}');
            if (sep < 0)
                return (size_t)-1;
            if (sep == 0)
                break;
        }
    }
    /* any further elements: the DOM ignores them, so consume and discard */
    for (;;) {
        int sep = jw_after(s, n, &i, ']');
        if (sep < 0)
            return (size_t)-1;
        if (sep == 0)
            return i;
        i = jw_value(s, n, i, 1);
        if (i == (size_t)-1)
            return (size_t)-1;
    }
}

static int delta_fast_scan(const char *s, size_t n, struct delta_hit *h)
{
    memset(h, 0, sizeof *h);
    size_t i = jw(s, n, 0);
    if (i >= n || s[i] != '{')
        return 0;
    i = jw(s, n, i + 1);
    if (i < n && s[i] == '}')
        return 1; /* an empty object moves no state, in either path */
    struct str key;
    for (;;) {
        int m = jw_member(s, n, &i, &key);
        if (m < 0)
            return 0;
        if (m == 1)
            return 1;
        if (JKEY(key, "choices")) {
            i = scan_choice(s, n, i, h);
        } else if (JKEY(key, "usage")) {
            /* most chunks carry "usage":null; a real usage object stays with
             * the parser, which reads four token fields out of it */
            if (jw_is_null(s, n, i))
                i += 4;
            else
                return 0;
        } else if (JKEY(key, "error")) {
            return 0;
        } else {
            i = jw_value(s, n, i, 1);
        }
        if (i == (size_t)-1)
            return 0;
        int sep = jw_after(s, n, &i, '}');
        if (sep < 0)
            return 0;
        if (sep == 0)
            return 1;
    }
}

/* --- the three appliers both paths share --------------------------------- */

static void stream_apply_text(void (*hook)(const char *, size_t),
                              struct buf *dst, struct str raw)
{
    if (!raw.n)
        return;
    size_t at = dst->len;
    jdecode_str(raw, dst);
    if (hook)
        hook(dst->p + at, dst->len - at);
}

static void stream_apply_finish(struct stream_state *st, struct str reason)
{
    if (str_eqc(reason, "tool_calls"))
        st->finish = FINISH_TOOL_CALLS;
    else if (str_eqc(reason, "length"))
        st->finish = FINISH_LENGTH;
    else if (st->finish == FINISH_NONE)
        st->finish = FINISH_STOP;
}

/* Fold one tool-call delta into the assembly: slot lookup by index, the
 * providers that leave `index` out (a fresh id opens a slot, a delta without
 * one continues the last), the name, the argument fragments and the live
 * byte/line counter. Exactly one implementation, fed by either reader. */
static void stream_apply_call(struct stream_state *st,
                              const struct call_delta *d)
{
    char *new_id = d->id.n ? jdecode_dupz(d->id) : NULL;
    size_t last = st->n_calls ? st->n_calls - 1 : 0;
    size_t idx = (size_t)d->index;
    if (!d->has_index) {
        if (new_id && st->n_calls > 0
            && strcmp(st->calls[last].id ? st->calls[last].id : "", new_id)
                != 0)
            idx = (size_t)st->n_calls;
        else
            idx = last;
    }
    struct stream_call *call = stream_call_by_index(st, idx);
    if (new_id) {
        free(call->id);
        call->id = new_id;
    }
    if (d->name.n) {
        free(call->name);
        call->name = jdecode_dupz(d->name);
    }
    if (d->args.n) {
        size_t at = call->args.len;
        jdecode_str(d->args, &call->args);
        gen_progress(call->name, &call->args, at);
    }
}

static void stream_apply_hit(struct stream_state *st,
                             const struct stream_hooks *hooks,
                             const struct delta_hit *h)
{
    if (h->finish_ok)
        stream_apply_finish(st, h->finish);
    if (h->saw_reasoning)
        stream_apply_text(hooks->think, &st->reasoning, h->reasoning);
    else if (h->saw_reasoning_alt)
        stream_apply_text(hooks->think, &st->reasoning,
                          h->reasoning_alt);
    if (h->content_ok)
        stream_apply_text(hooks->text, &st->content, h->content);
    for (int k = 0; k < h->n_calls; k++)
        stream_apply_call(st, &h->calls[k]);
}

/* The delta reader: a zero-allocation scan, with the DOM as fallback for
 * anything the scan is not certain about. tmp/bench.c builds with
 * KK_TEST_SEAMS and flips the switch to push every event down both paths and
 * compare the assembly; shipping builds get neither the global nor the test. */
#ifdef KK_TEST_SEAMS
static int g_delta_fast_off;
#define DELTA_SCAN(p, n, h) (!g_delta_fast_off && delta_fast_scan((p), (n), (h)))
#else
#define DELTA_SCAN(p, n, h) delta_fast_scan((p), (n), (h))
#endif

/* One SSE data payload: parse and fold into state + hooks. Decoded deltas
 * go straight into their owning buffers — the hooks render from the
 * appended range, so no scratch copy per delta is needed. */
static void stream_handle_data(struct str data, void *user)
{
    struct chat_request *cr = user;
    struct stream_state *st = cr->st;

    if (str_eqc(data, "[DONE]")) {
        if (st->finish == FINISH_NONE)
            st->finish = FINISH_STOP;
        return;
    }

    struct delta_hit dh;
    if (DELTA_SCAN(data.p, data.n, &dh)) {
        stream_apply_hit(st, &cr->hooks, &dh);
        return;
    }

    arena_reset(&cr->arena);
    struct jnode *root = json_parse(&cr->arena, data.p, data.n);
    if (!root || root->tag != J_OBJ)
        return;

    struct jnode *jerr = jobj_get(root, "error");
    if (jerr) {
        struct jnode *msg = jerr->tag == J_OBJ ? jobj_get(jerr, "message") : jerr;
        char *m = msg ? jstr_dupz(msg) : NULL;
        const char *text = m ? m : "api error";
        if (st->error) {
            char *joined = xasprintf("%s; %s", st->error, text);
            free(st->error);
            st->error = joined;
        } else {
            st->error = xstrdup(text);
        }
        free(m);
        st->finish = FINISH_ERROR;
        return;
    }

    struct jnode *usage = jobj_get(root, "usage");
    if (usage) {
        struct jnode *pt = jobj_get(usage, "prompt_tokens");
        struct jnode *ct = jobj_get(usage, "completion_tokens");
        if (pt) {
            st->prompt_tokens = jnum_i(pt);
            st->got_usage = 1;
        }
        if (ct) {
            st->completion_tokens = jnum_i(ct);
            st->got_usage = 1;
        }
        /* cache hit: OpenAI-style details or DeepSeek-style flat field */
        struct jnode *ptd = jobj_get(usage, "prompt_tokens_details");
        if (ptd && ptd->tag == J_OBJ) {
            struct jnode *cch = jobj_get(ptd, "cached_tokens");
            if (cch) {
                st->cache_tokens = jnum_i(cch);
                st->has_cache = 1;
            }
        }
        struct jnode *hit = jobj_get(usage, "prompt_cache_hit_tokens");
        if (hit) {
            st->cache_tokens = jnum_i(hit);
            st->has_cache = 1;
        }
    }

    struct jnode *choices = jobj_get(root, "choices");
    if (!choices || choices->tag != J_ARR || !choices->head)
        return;
    struct jnode *choice = choices->head;

    struct jnode *jfinish = jobj_get(choice, "finish_reason");
    if (jfinish && jfinish->tag == J_STR)
        stream_apply_finish(st, jfinish->raw);

    struct jnode *delta = jobj_get(choice, "delta");
    if (!delta)
        return;

    struct jnode *r = jobj_get(delta, "reasoning_content");
    if (!r)
        r = jobj_get(delta, "reasoning");
    if (r && r->tag == J_STR)
        stream_apply_text(cr->hooks.think, &st->reasoning, r->raw);

    struct jnode *t = jobj_get(delta, "content");
    if (t && t->tag == J_STR)
        stream_apply_text(cr->hooks.text, &st->content, t->raw);

    struct jnode *tcalls = jobj_get(delta, "tool_calls");
    if (tcalls && tcalls->tag == J_ARR) {
        for (struct jnode *item = tcalls->head; item; item = item->next) {
            if (item->tag != J_OBJ)
                continue;
            /* Read the event into the same shape the fast scan produces; the
             * assembly itself lives in stream_apply_call only. */
            struct call_delta d;
            memset(&d, 0, sizeof d);
            struct jnode *jidx = jobj_get(item, "index");
            if (jidx) {
                d.has_index = 1;
                d.index = jnum_i(jidx);
            }
            struct jnode *jid = jobj_get(item, "id");
            if (jid && jid->tag == J_STR && jid->raw.n > 0)
                d.id = jid->raw;
            struct jnode *fn = jobj_get(item, "function");
            if (fn && fn->tag == J_OBJ) {
                struct jnode *name = jobj_get(fn, "name");
                if (name && name->tag == J_STR && name->raw.n > 0)
                    d.name = name->raw;
                struct jnode *args = jobj_get(fn, "arguments");
                if (args && args->tag == J_STR && args->raw.n > 0)
                    d.args = args->raw;
            }
            stream_apply_call(st, &d);
        }
    }
}

/* Transport bytes -> SSE events -> delta assembly. */
/* A model that falls into a degenerate loop emits the same span over and over:
 * one captured run produced 757,988 characters that were 98% one repeated
 * sentence. Demand that the newest block has already turned up twice in the
 * recent window, so legitimate repetition (a markdown table, a progress log)
 * cannot trip it. */
#define LOOP_BLK 64
#define LOOP_WIN 8192
static int content_looping(const struct buf *b)
{
    size_t len = b->len;
    if (len < LOOP_BLK * 3)
        return 0;
    const char *tail = b->p + len - LOOP_BLK;
    const char *p = len > LOOP_WIN ? tail - LOOP_WIN : b->p;
    if (p < b->p)
        p = b->p;
    int hits = 0;
    /* the first byte decides almost every position: memchr scans it
     * vectorized, the memcmp only runs on a first-byte hit. The span stops
     * at the last legal start (tail - LOOP_BLK), exactly like the scalar
     * loop's condition did. */
    for (; p + LOOP_BLK <= tail;) {
        size_t span = (size_t)(tail - LOOP_BLK - p) + 1;
        const char *hit = (const char *)memchr(p, tail[0], span);
        if (!hit)
            break;
        if (memcmp(hit, tail, LOOP_BLK) == 0) {
            if (++hits >= 2)
                return 1;
            p = hit + LOOP_BLK;
        } else {
            p = hit + 1;
        }
    }
    return 0;
}

static int sse_on_bytes(const char *bytes, size_t n, void *user)
{
    struct chat_request *cr = user;
    sse_feed(&cr->sse, bytes, n, stream_handle_data, cr);
    if (InterlockedCompareExchange(&g_cancel, 0, 0))
        return 1;
    /* scan once per half-kilobyte of new text: the window is small enough
     * that this is noise next to the network it is watching. Nothing is
     * examined below 4KB, so a short deliberate repetition stays legal. */
    struct stream_state *st = cr->st;
    if (!st->loop_next)
        st->loop_next = 4096;
    if (st->content.len >= st->loop_next) {
        st->loop_next = st->content.len + 512;
        if (content_looping(&st->content)) {
            st->looped = 1;
            return 1;
        }
    }
    return 0;
}

/* ==========================================================================
 * 7. tools — read / write / bash / find / grep
 * ========================================================================== */

/* --- conversation (provider-shaped but provider-independent at heart) -- */

struct tool_call_rec {
    char *id;
    char *name;
    char *args; /* JSON string, owned */
};

struct image_part {
    char *mime; /* "image/png" etc. */
    char *b64;  /* base64 payload */
};

struct message {
    char *role;    /* system | user | assistant | tool */
    char *content; /* owned, may be NULL */
    struct tool_call_rec *calls;
    size_t n_calls;
    char *tool_call_id; /* role == tool */
    char *json_cache;   /* request-JSON fragment, built on first use */
    size_t json_cache_len;
    DA(struct image_part) images; /* attachments for vision models */
};

struct conversation {
    DA(struct message) msgs;
};

static void conv_init(struct conversation *cv)
{
    memset(cv, 0, sizeof *cv);
}

/* Transfer ownership of a heap content string into a new message. */
static struct message *conv_add_take(struct conversation *cv, const char *role,
                                     char *content)
{
    struct message m;
    memset(&m, 0, sizeof m);
    m.role = xstrdup(role);
    m.content = content; /* ownership moves */
    DA_PUSH(cv->msgs, m);
    return &cv->msgs.p[cv->msgs.n - 1];
}

static struct message *conv_add(struct conversation *cv, const char *role,
                                const char *content)
{
    return conv_add_take(cv, role, content ? xstrdup(content) : NULL);
}

/* Insert a user message at the FRONT of the conversation. A compaction
 * summary leads the retained tail — appending it would place it after
 * the newest user message and invert the story the model reads. Takes
 * ownership of content. */
static void conv_prepend_user(struct conversation *cv, char *content)
{
    struct message m;
    memset(&m, 0, sizeof m);
    m.role = xstrdup("user");
    m.content = content;
    DA_PUSH(cv->msgs, m);
    memmove(cv->msgs.p + 1, cv->msgs.p,
            (cv->msgs.n - 1) * sizeof *cv->msgs.p);
    cv->msgs.p[0] = m;
}

/* Release messages [from, to). Shared by /undo, /new and conv_free. */
static void conv_release_range(struct conversation *cv, size_t from,
                               size_t to)
{
    for (size_t i = from; i < to; i++) {
        struct message *m = &cv->msgs.p[i];
        free(m->role);
        free(m->content);
        free(m->tool_call_id);
        free(m->json_cache);
        for (size_t k = 0; k < m->images.n; k++) {
            free(m->images.p[k].mime);
            free(m->images.p[k].b64);
        }
        DA_FREE(m->images);
        for (size_t k = 0; k < m->n_calls; k++) {
            free(m->calls[k].id);
            free(m->calls[k].name);
            free(m->calls[k].args);
        }
        free(m->calls);
    }
}

static void conv_truncate(struct conversation *cv, size_t from)
{
    conv_release_range(cv, from, cv->msgs.n);
    cv->msgs.n = from;
}

/* Drop the first n messages (compaction folds the head, keeps the tail). */
static void conv_drop_head(struct conversation *cv, size_t n)
{
    if (n == 0)
        return;
    if (n >= cv->msgs.n) {
        conv_truncate(cv, 0);
        return;
    }
    conv_release_range(cv, 0, n);
    memmove(cv->msgs.p, cv->msgs.p + n,
            (cv->msgs.n - n) * sizeof *cv->msgs.p);
    cv->msgs.n -= n;
}

static void conv_free(struct conversation *cv)
{
    conv_truncate(cv, 0);
    DA_FREE(cv->msgs);
    memset(cv, 0, sizeof *cv);
}

/* Serialize one message as request-JSON (wire=1) or a session-log record
 * (wire=0). The shapes differ only in the tool_calls member. */
static void msg_serialize(struct buf *b, const struct message *m, int wire)
{
    /* Size the fragment before writing a byte of it. Every member is written
     * from a length the caller already holds, and escaping only ever grows a
     * plain run by nothing — so this is exact for the overwhelmingly common
     * escape-free message and one doubling short for the rest. Without it a
     * 100KB tool result grew through ~10 doublings, each copying everything
     * written so far. */
    size_t need = 192 + strlen(m->role);
    if (m->content)
        need += strlen(m->content);
    if (m->tool_call_id)
        need += strlen(m->tool_call_id);
    for (size_t i = 0; i < m->n_calls; i++) {
        need += strlen(m->calls[i].id) + strlen(m->calls[i].name);
        if (m->calls[i].args)
            need += strlen(m->calls[i].args);
    }
    for (size_t i = 0; i < m->images.n; i++)
        need += strlen(m->images.p[i].mime) + strlen(m->images.p[i].b64);
    buf_reserve(b, need);

    buf_appends(b, wire ? "{\"role\":\"" : "{\"type\":\"message\",\"role\":\"");
    json_escape_append(b, m->role, strlen(m->role));
    buf_appends(b, "\",\"content\":");
    if (m->images.n > 0) {
        if (wire) {
            /* multipart content: vision models read the images inline */
            buf_appends(b, "[{\"type\":\"text\",\"text\":\"");
            json_escape_append(b, m->content ? m->content : "",
                               m->content ? strlen(m->content) : 0);
            buf_appends(b, "\"}");
            for (size_t k = 0; k < m->images.n; k++) {
                buf_appends(b, ",{\"type\":\"image_url\",\"image_url\":"
                               "{\"url\":\"data:");
                buf_appends(b, m->images.p[k].mime);
                buf_appends(b, ";base64,");
                buf_appends(b, m->images.p[k].b64);
                buf_appends(b, "\"}}");
            }
            buf_appends(b, "]");
        } else {
            /* session log: string content, images ride beside it */
            if (m->content) {
                buf_appends(b, "\"");
                json_escape_append(b, m->content, strlen(m->content));
                buf_appends(b, "\"");
            } else {
                buf_appends(b, "null");
            }
            buf_appends(b, ",\"images\":[");
            for (size_t k = 0; k < m->images.n; k++) {
                if (k)
                    buf_appendc(b, ',');
                buf_appends(b, "{\"mime\":\"");
                buf_appends(b, m->images.p[k].mime);
                buf_appends(b, "\",\"data\":\"");
                buf_appends(b, m->images.p[k].b64);
                buf_appends(b, "\"}");
            }
            buf_appends(b, "]");
        }
    } else if (m->content) {
        buf_appends(b, "\"");
        json_escape_append(b, m->content, strlen(m->content));
        buf_appends(b, "\"");
    } else {
        buf_appends(b, "null");
    }
    if (m->n_calls > 0) {
        buf_appends(b, ",\"tool_calls\":[");
        for (size_t i = 0; i < m->n_calls; i++) {
            if (i)
                buf_appendc(b, ',');
            buf_appends(b, "{\"id\":\"");
            json_escape_append(b, m->calls[i].id, strlen(m->calls[i].id));
            buf_appends(b, wire ? "\",\"type\":\"function\",\"function\":{\"name\":\""
                                : "\",\"name\":\"");
            json_escape_append(b, m->calls[i].name, strlen(m->calls[i].name));
            buf_appends(b, "\",\"arguments\":");
            /* arguments is itself a JSON string holding the raw args text */
            buf_appends(b, "\"");
            json_escape_append(b, m->calls[i].args ? m->calls[i].args : "",
                               m->calls[i].args ? strlen(m->calls[i].args) : 0);
            buf_appends(b, wire ? "\"}}" : "\"}");
        }
        buf_appends(b, "]");
    }
    if (m->tool_call_id) {
        buf_appends(b, ",\"tool_call_id\":\"");
        json_escape_append(b, m->tool_call_id, strlen(m->tool_call_id));
        buf_appends(b, "\"");
    }
    buf_appends(b, "}");
}

/* --- tool specs --------------------------------------------------------- */

/* Image attachment a tool produced alongside its text output; owned by the
 * caller, moved into the tool-result message. */
struct tool_img {
    char *b64;
    char *mime;
};

struct tool_spec {
    const char *name;
    const char *description;
    const char *params;       /* JSON Schema "properties" object */
    char *(*exec)(const struct jnode *args, struct tool_img *img);
    const char *summary_key;  /* arg shown on the ● line */
    int quiet_ok;             /* 1: successful output stays model-only */
};

static char *tool_read(const struct jnode *args, struct tool_img *img);
static char *tool_write(const struct jnode *args, struct tool_img *img);
static char *tool_bash(const struct jnode *args, struct tool_img *img);
static char *tool_find(const struct jnode *args, struct tool_img *img);
static char *tool_grep(const struct jnode *args, struct tool_img *img);

/* the tool registry: adding a tool is one row here plus its exec fn */
static const struct tool_spec KK_TOOLS[] = {
    {
        "read",
        "Read a text file. Returns numbered lines (line numbers are NOT part "
        "of the file content). Use offset/limit to page through large files; "
        "re-read after editing to verify. Very long lines are cut at 400 "
        "columns and marked …[line truncated] — never copy a cut line into "
        "write old_string. When the file has more lines, the result states "
        "its range and the offset to continue from. Images (png, jpg, gif, "
        "webp) are returned as attachments for vision models.",
        "{\"path\":{\"type\":\"string\",\"description\":\"file path\"},"
        "\"offset\":{\"type\":\"integer\",\"description\":\"1-based first "
        "line (default 1)\"},"
        "\"limit\":{\"type\":\"integer\",\"description\":\"max lines to "
        "return (default 2000)\"}}",
        tool_read,
        "path",
        1,
    },
    {
        "write",
        "Create a new file, overwrite a file, or make a precise replacement "
        "in one. With only path and content: create or overwrite the whole "
        "file. With old_string also set: content replaces the FIRST exact "
        "occurrence of old_string — copy old_string byte-for-byte from the "
        "read output (same indentation), never include line numbers, and add "
        "surrounding lines to make it unique (it must appear exactly once, "
        "or set replace_all). Prefer this replacement mode for existing "
        "files; re-read afterwards to verify.",
        "{\"path\":{\"type\":\"string\",\"description\":\"file path\"},"
        "\"content\":{\"type\":\"string\",\"description\":\"full file "
        "content (overwrite mode) or replacement text (replace mode)\"},"
        "\"old_string\":{\"type\":\"string\",\"description\":\"exact text "
        "to replace; omit for create/overwrite\"},"
        "\"replace_all\":{\"type\":\"boolean\",\"description\":\"replace "
        "every occurrence (default false)\"}}",
        tool_write,
        "path",
        0,
    },
    {
        "bash",
        "Run a shell command (PowerShell) and return its combined output "
        "and exit code. Calls share one persistent session: the working "
        "directory and environment carry over between calls, and the "
        "exit code is PowerShell's $LASTEXITCODE. Errors stop the "
        "command ($ErrorActionPreference is Stop): a failing cmdlet "
        "aborts the rest of the command line, reports the error, and "
        "yields exit 1 — chain steps with explicit -ErrorAction or "
        "try/catch when continuation is intended. Each call costs a "
        "round-trip through the shell, so keep it for what the other "
        "tools cannot do (git, builds, running programs, processes): "
        "listing files is find, searching contents is grep, reading a "
        "known file is read.",
        "{\"command\":{\"type\":\"string\",\"description\":\"the command to "
        "run\"},"
        "\"timeout_ms\":{\"type\":\"integer\",\"description\":\"kill after "
        "this long (default 120000, capped at 600000)\"}}",
        tool_bash,
        "command",
        0,
    },
    {
        "find",
        "Find files in the workspace by NAME (not content), and answer "
        "\"what is here\": with no arguments it lists the most-touched "
        "files, a fragment like kk or render fuzzy-matches paths, a glob "
        "like *.c or src/**/*test* filters by pattern. Use this instead of "
        "shell Get-ChildItem/dir/ls — it reads a warm in-process index, so "
        "it costs far less than running a command. Ranking learns which "
        "files this workspace touches most. Returns relative paths with "
        "sizes and git status, 20 per page, rooted where kk started (a "
        "bash cd does not move it).",
        "{\"query\":{\"type\":\"string\",\"description\":\"fuzzy file name "
        "query, e.g. kk or render\"},"
        "\"glob\":{\"type\":\"string\",\"description\":\"optional glob "
        "pattern like *.py or src/**/*test*; overrides query\"},"
        "\"offset\":{\"type\":\"integer\",\"description\":\"0-based page "
        "index when more than 20 files match (default 0)\"}}",
        tool_find,
        "query",
        0,
    },
    {
        "grep",
        "Search file CONTENTS across the workspace. Use this instead of "
        "shell Select-String/findstr/grep, including when you already know "
        "the one file. Plain-text matching (smart_case: all-lowercase "
        "queries are case-insensitive); set regex for regular expressions. "
        "A query may carry a file filter like '*.rs pattern', 'src/ "
        "pattern' or 'kk.c pattern' (a bare name narrows to that file), and "
        "newlines turn it into a multi-pattern OR search in one pass. "
        "Definition lines are tagged [def]. Returns path:line:text matches "
        "with line numbers — use them to read or make a precise "
        "replacement.",
        "{\"query\":{\"type\":\"string\",\"description\":\"text to search "
        "for; optionally 'glob pattern' to filter files, or multiple "
        "patterns separated by newlines for OR search\"},"
        "\"regex\":{\"type\":\"boolean\",\"description\":\"treat the query "
        "as a regular expression (default false)\"},"
        "\"offset\":{\"type\":\"integer\",\"description\":\"file index to "
        "resume from after a time-budget cut (default 0)\"}}",
        tool_grep,
        "query",
        0,
    },
};

#define KK_N_TOOLS (sizeof KK_TOOLS / sizeof KK_TOOLS[0])

static const struct tool_spec *tool_lookup(const char *name)
{
    for (size_t i = 0; i < KK_N_TOOLS; i++)
        if (strcmp(KK_TOOLS[i].name, name) == 0)
            return &KK_TOOLS[i];
    return NULL;
}

/* --- args helpers ------------------------------------------------------- */

/* Tool arguments are slices of the parsed JSON, not per-arg heap strings.
 * A value with no escape is the source slice itself; an escaped one decodes
 * onto the tail of the shared buffer, whose capacity is fixed up front so
 * appending can never move it and earlier slices stay valid. */
struct args {
    const struct jnode *j;
    struct buf b;
};

static void args_init(struct args *a, const struct jnode *j)
{
    a->j = j;
    a->b = (struct buf)BUF_INIT;
    size_t need = 16;
    if (j) {
        for (struct jnode *pair = j->head; pair; pair = pair->next)
            if (pair->val && pair->val->tag == J_STR)
                need += pair->val->raw.n + 1;
    }
    buf_reserve(&a->b, need);
}

static struct str args_get(struct args *a, const char *key)
{
    struct jnode *v = jobj_get(a->j, key);
    if (!v || v->tag != J_STR)
        return (struct str){ NULL, 0 };
    if (!find_backslash(v->raw.p, v->raw.n))
        return v->raw;
    size_t at = a->b.len;
    jdecode_str(v->raw, &a->b);
    return (struct str){ a->b.p + at, a->b.len - at };
}

/* True when the key is present as a string (an empty value counts). */
static int args_has(const struct jnode *j, const char *key)
{
    struct jnode *v = jobj_get(j, key);
    return v && v->tag == J_STR;
}

static int64_t args_int(const struct jnode *args, const char *key,
                        int64_t fallback)
{
    struct jnode *v = jobj_get(args, key);
    return v ? jnum_i(v) : fallback;
}

/* Extract a one-line display summary from tool args, pi-style:
 * read path (行 X-Y), bash 命令, write 路径, find/grep 查询词.
 * The arg to show comes from the registry's summary_key. */
static char *args_summary(const struct jnode *args, const char *tool)
{
    const struct tool_spec *ts = tool_lookup(tool);
    if (!ts)
        return xstrdup("");
    if (strcmp(tool, "read") == 0) {
        char *path = jstr_dupz(jobj_get(args, "path"));
        if (path && *path) {
            int64_t offset = args_int(args, "offset", 1);
            int64_t limit = args_int(args, "limit", 0);
            char *out = limit > 0
                ? xasprintf("%s （行 %lld-%lld）", path, (long long)offset,
                            (long long)offset + limit - 1)
                : xstrdup(path);
            free(path);
            return out;
        }
        free(path);
    }
    char *s = jstr_dupz(jobj_get(args, ts->summary_key));
    if (!s || !*s) {
        free(s);
        s = jstr_dupz(jobj_get(args, "glob")); /* find's glob mode has no query */
        if (!s || !*s) {
            free(s);
            if (strcmp(tool, "find") == 0)
                return xstrdup("（列工作集）"); /* argument-less find */
            return xstrdup("");
        }
    }
    /* collapse to one line, cap length (never splitting a UTF-8 sequence) */
    size_t n = strlen(s);
    char *out = xmalloc(n + 1);
    size_t o = 0;
    for (size_t i = 0; i < n && o < 120; i++)
        out[o++] = (s[i] == '\n' || s[i] == '\r') ? ' ' : s[i];
    if (o == 120) {
        size_t k = o;
        while (k > 0 && ((unsigned char)out[k - 1] & 0xC0) == 0x80)
            k--;
        if (k > 0 && (unsigned char)out[k - 1] >= 0xC0)
            k--; /* lead byte whose continuation was cut off */
        o = k;
    }
    out[o] = '\0';
    free(s);
    return out;
}

/* --- file helpers ------------------------------------------------------- */

/* The one place a path is NUL-terminated: Win32 wants a wide string, and
 * the slash normalization runs on that buffer, so no UTF-8 copy exists
 * just to rewrite separators. */
static wchar_t *path_to_w(struct str path)
{
    wchar_t *w = w_from_utf8_n(path.p, path.n);
    for (wchar_t *c = w; c && *c; c++)
        if (*c == L'/')
            *c = L'\\';
    return w;
}

#define FILE_READ_CAP (4 * 1024 * 1024)
#define SESSION_READ_CAP (64 * 1024 * 1024)

/* The one file reader every consumer shares. cap>0 refuses bigger files
 * (reporting the size through *too_big_at when given) and keeps tool reads
 * from malloc-ing monsters — session replay passes SESSION_READ_CAP for the
 * higher bound; head>0 reads at most that many bytes whatever the size.
 * share=0 doubles as the lock probe: an exclusive open fails with
 * ERROR_SHARING_VIOLATION exactly when another process holds the file. */
static char *file_slurp(struct str path, size_t *out_len, int *locked,
                        unsigned long long *too_big_at, long long cap,
                        size_t head)
{
    wchar_t *w = path_to_w(path);
    DWORD share = locked ? 0 : (FILE_SHARE_READ | FILE_SHARE_WRITE);
    HANDLE f = CreateFileW(w, GENERIC_READ, share, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (locked)
        *locked = 0;
    if (f == INVALID_HANDLE_VALUE) {
        if (locked && GetLastError() == ERROR_SHARING_VIOLATION)
            *locked = 1;
        return NULL;
    }
    LARGE_INTEGER sz;
    int sized = GetFileSizeEx(f, &sz) != 0;
    if (!sized || (cap && sz.QuadPart > cap)) {
        if (too_big_at)
            *too_big_at = sized && cap && sz.QuadPart > cap
                              ? (unsigned long long)sz.QuadPart
                              : 0;
        CloseHandle(f);
        return NULL;
    }
    size_t n = (size_t)sz.QuadPart;
    if (head && n > head)
        n = head;
    char *data = xmalloc(n + 1);
    DWORD got = 0;
    ReadFile(f, data, (DWORD)n, &got, NULL);
    CloseHandle(f);
    data[got] = '\0';
    *out_len = got;
    return data;
}

static char *file_read_all(struct str path, size_t *out_len)
{
    return file_slurp(path, out_len, NULL, NULL, FILE_READ_CAP, 0);
}

/* The first cap bytes whatever the file size — file_slurp refuses anything
 * larger instead of truncating, and a SKILL.md body runs to 17KB while only
 * its frontmatter is of interest. */
static char *file_read_head(struct str path, size_t cap, size_t *out_len)
{
    return file_slurp(path, out_len, NULL, NULL, 0, cap);
}

static int file_write_all(struct str path, const char *data, size_t n)
{
    /* create parent directories, one level per separator */
    const char *slash = mem_rfind(path.p, path.n, '/');
    const char *back = mem_rfind(path.p, path.n, '\\');
    if (back > slash)
        slash = back;
    if (slash && slash != path.p) {
        struct str dir = { path.p, (size_t)(slash - path.p) };
        wchar_t *wdir = path_to_w(dir); /* also normalizes '/' */
        for (wchar_t *c = wdir + 1; *c; c++) {
            if (*c == L'\\' || *c == L'/') {
                wchar_t save = *c;
                *c = 0;
                CreateDirectoryW(wdir, NULL);
                *c = save;
            }
        }
        CreateDirectoryW(wdir, NULL);
        free(wdir);
    }

    /* atomic: write a temp sibling, then rename over the target — a crash
     * mid-write can no longer truncate the original. w stays alive until
     * after the rename: MoveFileExW reads it, and free()'d small blocks
     * get heap bookkeeping written over their first bytes (ASan caught
     * this exact use-after-free — short paths renamed to garbage). */
    wchar_t *w = path_to_w(path);
    size_t wlen = wcslen(w);
    wchar_t *wtmp = xmalloc((wlen + 24) * sizeof(wchar_t));
    memcpy(wtmp, w, wlen * sizeof(wchar_t));
    swprintf(wtmp + wlen, 24, L".tmp%lu~", (unsigned long)GetCurrentProcessId());
    HANDLE f = CreateFileW(wtmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        free(w);
        free(wtmp);
        return -1;
    }
    DWORD wrote = 0;
    int ok = WriteFile(f, data, (DWORD)n, &wrote, NULL) && wrote == n;
    CloseHandle(f);
    if (!ok) {
        DeleteFileW(wtmp);
        free(wtmp);
        free(w);
        return -1;
    }
    ok = MoveFileExW(wtmp, w, MOVEFILE_REPLACE_EXISTING
                                 | MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok)
        DeleteFileW(wtmp);
    free(wtmp);
    free(w);
    return ok ? 0 : -1;
}

/* Probe whether a path is locked by another process (editors hold their
 * files open exclusively-ish; sharing violations surface here). */
static int file_locked(struct str path)
{
    wchar_t *w = path_to_w(path);
    HANDLE f = CreateFileW(w, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (f == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_SHARING_VIOLATION;
    CloseHandle(f);
    return 0;
}

/* --- fff: fuzzy file finder + content grep (Rust cdylib) ---------------- */

/* Both index tools refuse the same way when the DLL is absent. */
#define FFF_UNAVAIL_ERR "error: 文件索引不可用（fff DLL 未随 kk.exe 提供）"

/* The DLL ships next to kk.exe and loads lazily on the first find/grep
 * tool call. Without it those tools return an error and the agent falls
 * back to bash pipelines. fff.h provides the struct layouts; the functions
 * resolve through LoadLibrary (no import library ships with the DLL). */
static void *fff_inst;
static int fff_tried, fff_ok;
static SRWLOCK fff_lock = SRWLOCK_INIT;

/* The DLL's C ABI resolved onto one struct: "does this fff.dll have the
 * newer entry point" is a NULL member test, not a file-scope global. */
static struct {
    struct FffResult *(*create)(struct FffCreateOptions);
    struct FffResult *(*search)(void *, const char *, const char *, uint32_t,
                                uint32_t, uint32_t, int32_t, uint32_t);
    struct FffResult *(*grep)(void *, const char *, uint8_t, uint64_t,
                              uint32_t, bool, uint32_t, uint32_t, uint64_t,
                              uint32_t, uint32_t, bool);
    struct FffResult *(*glob)(void *, const char *, const char *, uint32_t,
                              uint32_t, uint32_t);
    struct FffResult *(*multi_grep)(void *, const char *, const char *,
                                    uint64_t, uint32_t, bool, uint32_t,
                                    uint32_t, uint64_t, uint32_t, uint32_t,
                                    bool);
    struct FffResult *(*grep_ex)(void *, const char *, uint8_t, uint64_t,
                                 uint32_t, bool, uint32_t, uint32_t, uint64_t,
                                 bool, uint32_t, uint32_t, bool);
    struct FffResult *(*track)(void *, const char *, const char *);
    bool (*is_scanning)(void *);
    struct FffResult *(*scan)(void *);
    struct FffResult *(*refresh_git)(void *);
    struct FffResult *(*wait)(void *, uint64_t);
    struct FffResult *(*wait_watcher)(void *, uint64_t);
    void (*free_result)(struct FffResult *);
    void (*free_search)(struct FffSearchResult *);
    void (*free_grep)(struct FffGrepResult *);
} fff;

/* The first FFF_REQUIRED are mandatory; the rest only cost a newer feature
 * when an older fff.dll ships next to kk.exe. */
#define FFF_REQUIRED 8
static const struct {
    const char *name;
    void **slot;
} fff_exports[] = {
    { "fff_create_instance_with_value", (void **)&fff.create },
    { "fff_search", (void **)&fff.search },
    { "fff_live_grep", (void **)&fff.grep },
    { "fff_scan_files", (void **)&fff.scan },
    { "fff_wait_for_scan", (void **)&fff.wait },
    { "fff_free_result", (void **)&fff.free_result },
    { "fff_free_search_result", (void **)&fff.free_search },
    { "fff_free_grep_result", (void **)&fff.free_grep },
    { "fff_glob", (void **)&fff.glob },
    { "fff_multi_grep", (void **)&fff.multi_grep },
    { "fff_track_query", (void **)&fff.track },
    { "fff_wait_for_watcher", (void **)&fff.wait_watcher },
    { "fff_live_grep_ex", (void **)&fff.grep_ex },
    { "fff_refresh_git_status", (void **)&fff.refresh_git },
    { "fff_is_scanning", (void **)&fff.is_scanning },
};

/* LoadLibrary + resolve every export the tools use. */
static void fff_load(void)
{
    if (fff_tried)
        return;
    fff_tried = 1;
    HMODULE mod = LoadLibraryW(L"fff.dll");
    if (!mod)
        return;
    for (size_t i = 0; i < sizeof fff_exports / sizeof fff_exports[0]; i++) {
        *fff_exports[i].slot = (void *)GetProcAddress(mod, fff_exports[i].name);
        if (!*fff_exports[i].slot && i < FFF_REQUIRED)
            return; /* a missing required export marks the DLL unusable */
    }
    fff_ok = 1;
}

/* Load the DLL, create an instance rooted at the cwd, and wait (bounded)
 * for the initial index scan. The instance lives for the process. The
 * lock makes it safe to warm on a startup thread while a find/grep call
 * arrives; the call waits for the warmup instead of building a second
 * instance. */
static int fff_ensure(void)
{
    /* fff_load marks fff_tried before it does any work and only sets fff_ok
     * at the end, so calling it outside the lock let a second thread see
     * "tried but not ok" and give up on the index entirely. It is reachable
     * now that the main thread also warms fff, not just the startup thread. */
    AcquireSRWLockExclusive(&fff_lock);
    fff_load();
    if (!fff_ok) {
        ReleaseSRWLockExclusive(&fff_lock);
        return 0;
    }
    if (!fff_inst) {
        /* frecency + query history DBs persist under %LOCALAPPDATA%\kk\fff:
         * ranking learns which files this workspace keeps touching, and
         * find/grep results get sharper over the life of the workspace */
        static char *db_frecency, *db_history;
        if (!db_frecency) {
            char *la = env_get("LOCALAPPDATA");
            char *kkdir = xasprintf("%s\\kk", la ? la : ".");
            free(la);
            CreateDirectoryA(kkdir, NULL);
            char *dir = xasprintf("%s\\fff", kkdir);
            CreateDirectoryA(dir, NULL);
            db_frecency = xasprintf("%s\\frecency", dir);
            db_history = xasprintf("%s\\history", dir);
            free(kkdir);
            free(dir);
        }
        struct FffCreateOptions o;
        memset(&o, 0, sizeof o);
        o.version = FFF_CREATE_OPTIONS_VERSION;
        o.base_path = ".";
        o.frecency_db_path = db_frecency;
        o.history_db_path = db_history;
        o.enable_mmap_cache = 1;
        o.enable_content_indexing = 1;
        o.watch = 1;
        o.ai_mode = 1;
        struct FffResult *r = fff.create(o);
        if (!r || !r->success || !r->handle) {
            if (r)
                fff.free_result(r);
            ReleaseSRWLockExclusive(&fff_lock);
            return 0;
        }
        fff_inst = r->handle;
        fff.free_result(r);
        fff.scan(fff_inst);
        fff.wait(fff_inst, 10000); /* bound the wait; late files join the index */
        if (fff.wait_watcher)
            fff.wait_watcher(fff_inst, 2000); /* live edits from here on */
    }
    ReleaseSRWLockExclusive(&fff_lock);
    return 1;
}

/* Background warmup: pre-index the workspace at startup so the first
 * find/grep tool call answers from a ready index instead of stalling on
 * the initial scan. */
static DWORD WINAPI fff_warmup(LPVOID arg)
{
    (void)arg;
    fff_ensure();
    return 0;
}

/* kk changed a file: re-index it and refresh the git-status cache — a
 * write flips the file's clean/modified state that find reports. */
static void fff_note_write(void)
{
    if (!fff_ok || !fff_inst)
        return;
    fff.scan(fff_inst);
    if (fff.refresh_git) {
        struct FffResult *g = fff.refresh_git(fff_inst);
        if (g)
            fff.free_result(g);
    }
}

/* --- read/grep shared caps ----------------------------------------------- */

/* One output line is cut at this many display columns: source lines
 * beyond it are unusable for exact replacement anyway, and a single
 * minified or base64 line could otherwise dump megabytes into the
 * conversation. The cut is marked so the model never copies a cut line
 * into write old_string. */
#define KK_LINE_COLS 400

/* True when the first llen bytes are only spaces, tabs or CRs. */
static int blank_line(const char *s, size_t llen)
{
    for (size_t k = 0; k < llen; k++)
        if (s[k] != ' ' && s[k] != '\t' && s[k] != '\r')
            return 0;
    return 1;
}

/* A line-number prefix and a column-capped line, with ONE capacity
 * reservation. The read tool does this per line of a page; as two appends it
 * cost two reserve checks and two copies per line to add an eight-byte prefix.
 * Capping only ever removes bytes, and the worst tail it can add is the
 * truncation marker plus the newline, so pn + n + 24 is always enough. */
static void buf_append_line_capped_pfx(struct buf *out, const char *pre,
                                       size_t pn, const char *s, size_t n)
{
    /* The ordinary line — printable ASCII, short enough to fit whole — is
     * what source code and logs are made of: one reservation, two memcpys, no
     * per-codepoint decode and no NUL write per run. A trailing CR rides
     * through with the width of 1 the general path would have given it. */
    size_t body = n;
    int cr = body && s[body - 1] == '\r';
    if (cr)
        body--;
    if (body + (cr ? 1u : 0u) <= (size_t)KK_LINE_COLS
        && ascii_run(s, body) == body) {
        buf_reserve(out, pn + body + 2);
        if (pn) {
            memcpy(out->p + out->len, pre, pn);
            out->len += pn;
        }
        memcpy(out->p + out->len, s, body);
        out->len += body;
        if (cr)
            out->p[out->len++] = '\r';
        out->p[out->len++] = '\n';
        out->p[out->len] = '\0';
        return;
    }
    buf_reserve(out, pn + n + 24);
    if (pn) {
        memcpy(out->p + out->len, pre, pn);
        out->len += pn;
    }
    size_t i = 0;
    int w = 0;
    while (i < n) {
        /* printable-ASCII run: one column per byte, copy in bulk */
        if ((unsigned char)s[i] >= 0x20 && (unsigned char)s[i] < 0x80) {
            size_t room = (size_t)(KK_LINE_COLS - w);
            if (room == 0)
                break;
            size_t start = i;
            size_t lim = i + (room < n - i ? room : n - i);
            i += ascii_run(s + i, lim - i);
            buf_append_n(out, s + start, i - start);
            w += (int)(i - start);
            continue;
        }
        uint32_t cp;
        size_t clen = u8_step(s + i, n - i, &cp);
        if (w + (int)u8_cp_width(cp) > KK_LINE_COLS)
            break;
        buf_append_n(out, s + i, clen);
        i += clen;
        w += (int)u8_cp_width(cp);
    }
    if (i < n)
        buf_appends(out, " …[line truncated]");
    buf_appendc(out, '\n');
}

static void buf_append_line_capped(struct buf *out, const char *s, size_t n)
{
    buf_append_line_capped_pfx(out, NULL, 0, s, n);
}

static char *tool_find(const struct jnode *args, struct tool_img *img_)
{
    (void)img_; /* only read attaches images */
    char *query = jstr_dupz(jobj_get(args, "query"));
    char *glob = jstr_dupz(jobj_get(args, "glob"));
    char *result = NULL;
    if (glob && !*glob) {
        result = xstrdup("error: find glob is empty; omit glob to search by "
                         "name, or pass no arguments to list the workspace");
        goto cleanup;
    }
    if (!fff_ensure()) {
        result = xstrdup(FFF_UNAVAIL_ERR);
        goto cleanup;
    }
    int64_t off = args_int(args, "offset", 0);
    if (off < 0)
        off = 0;
    const char *tracked = query;
    struct FffResult *r = NULL;
    if (glob && *glob && fff.glob) {
        tracked = glob; /* glob mode: rank by frecency, no fuzzy needed */
        r = fff.glob(fff_inst, glob, NULL, 0, (uint32_t)off, 20);
    } else {
        /* an empty query is fff's "whole index, ranked by frecency" */
        r = fff.search(fff_inst, query ? query : "", NULL, 0, (uint32_t)off,
                     20, 0, 0);
    }
    if (!r) {
        result = xstrdup("error: find failed");
        goto cleanup;
    }
    if (!r->success) {
        result = xasprintf("error: %s", r->error ? r->error : "find failed");
        fff.free_result(r);
        goto cleanup;
    }
    struct FffSearchResult *sr = r->handle;
    if (fff.track && sr->count > 0 && tracked && *tracked)
        fff.track(fff_inst, tracked, sr->items[0].relative_path);
    /* tracked points into query/glob: the frees must wait until after
     * fff.track (ASan caught this exact use-after-free) */
    free(query);
    free(glob);
    struct buf out = BUF_INIT;
    for (uint32_t i = 0; i < sr->count && i < 20; i++) {
        const struct FffFileItem *it = &sr->items[i];
        buf_appendf(&out, "%s (%llu bytes)", it->relative_path,
                    (unsigned long long)it->size);
        if (it->git_status && it->git_status[0])
            buf_appendf(&out, " [%s]", it->git_status);
        buf_appends(&out, "\n");
    }
    buf_appendf(&out, "%u of %u indexed files matched\n", sr->total_matched,
                sr->total_files);
    if (fff.is_scanning && fff.is_scanning(fff_inst))
        buf_appends(&out, "[workspace index still scanning: results may "
                          "be incomplete; re-run shortly]\n");
    /* offset is a fff page index, so the entry numbers have to be scaled
     * out of it — telling the model to re-run at off+count would skip
     * (count/20 - 1) whole pages */
    uint32_t first = (uint32_t)off * 20;
    if (sr->count > 0 && sr->total_matched > first + sr->count)
        buf_appendf(&out, "[showing entries %u-%u of %u; re-run with offset "
                          "%u for the next page]\n",
                    first + 1, first + sr->count, sr->total_matched,
                    (uint32_t)off + 1);
    fff.free_search(sr);
    fff.free_result(r);
    return buf_detach(&out);

cleanup:
    free(query);
    free(glob);
    return result;
}

/* One grep context line: dim two-space indent, capped content. */
static void grep_context_line(struct buf *out, const char *text)
{
    buf_appends(out, "  ");
    buf_append_line_capped(out, text ? text : "", text ? strlen(text) : 0);
}

static char *tool_grep(const struct jnode *args, struct tool_img *img_)
{
    (void)img_; /* only read attaches images */
    char *query = jstr_dupz(jobj_get(args, "query"));
    char *result = NULL;
    if (!query || !*query) {
        result = xstrdup("error: grep requires a query");
        goto cleanup;
    }
    if (!fff_ensure()) {
        result = xstrdup(FFF_UNAVAIL_ERR);
        goto cleanup;
    }
    struct jnode *rx = jobj_get(args, "regex");
    int mode = rx && rx->tag == J_TRUE ? 1 : 0; /* 0 plain SIMD, 1 regex */
    int64_t off = args_int(args, "offset", 0);
    if (off < 0)
        off = 0;
    /* 5 matches per file, 30 lines, 2s budget; smart_case: all-lowercase
     * queries search case-insensitively; 1 line of context on each side;
     * definitions tagged for structure-aware reading. A query holding
     * newlines fans out to the multi-pattern OR matcher in one pass.
     * The time budget also bounds zero-match walks, and next_file_offset
     * reports what the budget could not cover. */
    struct FffResult *r;
    if (fff.multi_grep && strchr(query, '\n'))
        r = fff.multi_grep(fff_inst, query, NULL, 0, 5, 1, (uint32_t)off, 30,
                         2000, 1, 1, 1);
    else if (fff.grep_ex)
        r = fff.grep_ex(fff_inst, query, (uint8_t)mode, 0, 5, 1, (uint32_t)off,
                      30, 2000, 1, 1, 1, 1);
    else
        r = fff.grep(fff_inst, query, (uint8_t)mode, 0, 5, 1, (uint32_t)off, 30,
                   2000, 1, 1, 1);
    free(query);
    if (!r)
        return xstrdup("error: grep failed");
    if (!r->success) {
        char *msg = xasprintf("error: %s", r->error ? r->error : "grep failed");
        fff.free_result(r);
        return msg;
    }
    struct FffGrepResult *gr = r->handle;
    struct buf out = BUF_INIT;
    uint32_t shown = 0;
    for (uint32_t i = 0; i < gr->count && i < 30; i++) {
        const struct FffGrepMatch *m = &gr->items[i];
        if (m->is_binary)
            continue;
        /* "before" lines must print above their match: after it, the model
         * reads the file backwards */
        for (uint32_t cb = 0; cb < m->context_before_count; cb++)
            grep_context_line(&out, m->context_before[cb]);
        buf_appendf(&out, "%s:%llu: ", m->relative_path,
                    (unsigned long long)m->line_number);
        if (m->is_definition)
            buf_appends(&out, "[def] ");
        buf_append_line_capped(&out, m->line_content ? m->line_content : "",
                               m->line_content ? strlen(m->line_content) : 0);
        for (uint32_t ca = 0; ca < m->context_after_count; ca++)
            grep_context_line(&out, m->context_after[ca]);
        shown++;
    }
    buf_appendf(&out, "%u matches\n", shown); /* binary hits are not shown */
    if (fff.is_scanning && fff.is_scanning(fff_inst))
        buf_appends(&out, "[workspace index still scanning: results may "
                          "be incomplete; re-run shortly]\n");
    if (gr->next_file_offset)
        buf_appendf(&out, "[time budget hit: files from offset %u are "
                          "unsearched; re-run with offset %u to continue]\n",
                    gr->next_file_offset, gr->next_file_offset);
    fff.free_grep(gr);
    fff.free_result(r);
    return buf_detach(&out);

cleanup:
    free(query);
    return result;
}

/* --- read ---------------------------------------------------------------- */

static char *b64_encode(const char *data, size_t n);

static const char *image_mime_of(struct str path, const char *data,
                                 size_t len);

/* Image formats vision models commonly accept, keyed by extension with
 * the magic bytes that confirm the extension told the truth. */
static const struct {
    const char *ext, *mime;
    const char *magic;
    int magic_len;
    int webp; /* RIFF container: "WEBP" at offset 8 confirms */
} known_image_exts[] = {
    { ".png", "image/png", "\x89PNG", 4, 0 },
    { ".jpg", "image/jpeg", "\xFF\xD8\xFF", 3, 0 },
    { ".jpeg", "image/jpeg", "\xFF\xD8\xFF", 3, 0 },
    { ".gif", "image/gif", "GIF", 3, 0 },
    { ".webp", "image/webp", "RIFF", 4, 1 },
};

/* --- clipboard image: CF_DIB -> PNG, no helper processes ----------------- */

/* The clipboard holds a Windows DIB; vision models want PNG. Encoding
 * happens in-process (CRC32 + zlib stored blocks): spawning PowerShell
 * STA for a .NET encoder was slow, fragile and beeped more often than
 * it pasted. 24/32bpp BI_RGB and 32bpp BITFIELDS cover every screenshot
 * and browser copy this sees in practice. */
static uint32_t png_crc_table[256];

static uint32_t png_crc32(const unsigned char *data, size_t n)
{
    if (!png_crc_table[1]) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            png_crc_table[i] = c;
        }
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++)
        c = png_crc_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

static void png_put_u32be(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

/* One PNG chunk: length, type, payload, CRC over type+payload. */
static void png_chunk(unsigned char *o, uint32_t len, const char *type,
                      const unsigned char *payload)
{
    png_put_u32be(o, len);
    memcpy(o + 4, type, 4);
    if (len)
        memcpy(o + 8, payload, len);
    uint32_t crc = png_crc32(o + 4, (size_t)len + 4);
    png_put_u32be(o + 8 + len, crc);
}

static uint32_t png_adler32(const unsigned char *data, size_t n)
{
    /* NMAX=5552: 255*5552 + 65521 still fits in 32 bits, so the modulo
     * runs once per ~5.5 KB instead of once per byte (zlib's trick). */
    uint32_t a = 1, b = 0;
    size_t i = 0;
    while (i < n) {
        size_t chunk = n - i < 5552 ? n - i : 5552;
        for (size_t k = 0; k < chunk; k++) {
            a += data[i + k];
            b += a;
        }
        a %= 65521;
        b %= 65521;
        i += chunk;
    }
    return (b << 16) | a;
}

/* Pixel dimensions from an image's header only (no decode: the point is to
 * refuse what the endpoint would refuse BEFORE paying a round for a rejected
 * request). Returns 0 when the shape was read. */
static int image_dims_of(const char *data, size_t len, const char *mime,
                         int *pw, int *ph)
{
    const unsigned char *d = (const unsigned char *)data;
    if (strcmp(mime, "image/png") == 0) {
        if (len < 24)
            return -1;
        *pw = (int)((uint32_t)d[16] << 24 | (uint32_t)d[17] << 16
                   | (uint32_t)d[18] << 8 | d[19]);
        *ph = (int)((uint32_t)d[20] << 24 | (uint32_t)d[21] << 16
                   | (uint32_t)d[22] << 8 | d[23]);
        return (*pw > 0 && *ph > 0) ? 0 : -1;
    }
    if (strcmp(mime, "image/gif") == 0) {
        if (len < 10)
            return -1;
        *pw = d[6] | (d[7] << 8);
        *ph = d[8] | (d[9] << 8);
        return 0;
    }
    if (strcmp(mime, "image/webp") == 0) {
        if (len < 30 || memcmp(d + 12, "VP8", 3) != 0)
            return -1;
        if (d[15] == ' ') { /* lossy: 14-bit dims after the start code */
            *pw = (int)(((uint32_t)d[26] | ((uint32_t)d[27] << 8)) & 0x3FFF);
            *ph = (int)(((uint32_t)d[28] | ((uint32_t)d[29] << 8)) & 0x3FFF);
            return 0;
        }
        if (d[15] == 'L') { /* lossless: two 14-bit fields, 1-based */
            uint32_t b = (uint32_t)d[21] | ((uint32_t)d[22] << 8)
                       | ((uint32_t)d[23] << 16) | ((uint32_t)d[24] << 24);
            *pw = (int)(b & 0x3FFF) + 1;
            *ph = (int)((b >> 14) & 0x3FFF) + 1;
            return 0;
        }
        if (d[15] == 'X') { /* extended: 24-bit dims minus one */
            *pw = (int)((uint32_t)d[24] | ((uint32_t)d[25] << 8)
                      | ((uint32_t)d[26] << 16)) + 1;
            *ph = (int)((uint32_t)d[27] | ((uint32_t)d[28] << 8)
                      | ((uint32_t)d[29] << 16)) + 1;
            return 0;
        }
        return -1;
    }
    if (strcmp(mime, "image/jpeg") == 0) {
        size_t i = 2; /* past SOI */
        while (i + 9 < len) {
            if (d[i] != 0xFF)
                return -1;
            unsigned m = d[i + 1];
            if (m == 0xD8 || m == 0x01 || (m >= 0xD0 && m <= 0xD7)) {
                i += 2; /* standalone markers carry no payload */
                continue;
            }
            if (m == 0xD9)
                return -1; /* EOI before any frame header */
            unsigned seg = (unsigned)d[i + 2] << 8 | d[i + 3];
            if (m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC) {
                *ph = (int)(((unsigned)d[i + 5] << 8) | d[i + 6]);
                *pw = (int)(((unsigned)d[i + 7] << 8) | d[i + 8]);
                return 0;
            }
            if (seg < 2)
                return -1;
            i += 2 + seg;
        }
        return -1;
    }
    return -1;
}

/* Decode a clipboard DIB into 8-bit RGB PNG bytes (heap, *out_len set),
 * or NULL when the format is one this does not handle. */
static unsigned char *dib_to_png(const unsigned char *dib, size_t dib_len,
                                 size_t *out_len)
{
    if (dib_len < 40)
        return NULL;
    uint32_t hdr = (uint32_t)dib[0] | ((uint32_t)dib[1] << 8)
        | ((uint32_t)dib[2] << 16) | ((uint32_t)dib[3] << 24);
    int32_t w = (int32_t)((uint32_t)dib[4] | ((uint32_t)dib[5] << 8)
        | ((uint32_t)dib[6] << 16) | ((uint32_t)dib[7] << 24));
    int32_t h = (int32_t)((uint32_t)dib[8] | ((uint32_t)dib[9] << 8)
        | ((uint32_t)dib[10] << 16) | ((uint32_t)dib[11] << 24));
    uint32_t bpp = (uint32_t)dib[14] | ((uint32_t)dib[15] << 8);
    uint32_t comp = (uint32_t)dib[16] | ((uint32_t)dib[17] << 8)
        | ((uint32_t)dib[18] << 16) | ((uint32_t)dib[19] << 24);
    if (w <= 0 || h == 0 || w > 16384 || (h > 0 ? h : -h) > 16384)
        return NULL;
    if (bpp != 24 && bpp != 32)
        return NULL;
    if (comp != 0 && comp != 3) /* BI_RGB or BI_BITFIELDS */
        return NULL;
    uint32_t rmask = 0xFF0000, gmask = 0xFF00, bmask = 0xFF;
    size_t pixel_off = hdr;
    if (comp == 3) {
        if (dib_len < 52)
            return NULL;
        /* the channel masks sit at offset 40 in every header shape
         * (BITMAPINFOHEADER+BITFIELDS and BITMAPV5HEADER alike) */
        rmask = (uint32_t)dib[40] | ((uint32_t)dib[41] << 8)
            | ((uint32_t)dib[42] << 16) | ((uint32_t)dib[43] << 24);
        gmask = (uint32_t)dib[44] | ((uint32_t)dib[45] << 8)
            | ((uint32_t)dib[46] << 16) | ((uint32_t)dib[47] << 24);
        bmask = (uint32_t)dib[48] | ((uint32_t)dib[49] << 8)
            | ((uint32_t)dib[50] << 16) | ((uint32_t)dib[51] << 24);
        if (hdr == 40)
            pixel_off = 52; /* BITMAPINFOHEADER: masks follow the header */
    }
    if (!rmask || !gmask || !bmask)
        return NULL;
    int rsh = 0, gsh = 0, bsh = 0;
    while (!(rmask >> rsh & 1))
        rsh++;
    while (!(gmask >> gsh & 1))
        gsh++;
    while (!(bmask >> bsh & 1))
        bsh++;

    size_t height = (size_t)(h > 0 ? h : -h);
    int top_down = h < 0;
    size_t row_bytes = (size_t)w * 3;
    size_t stride = bpp == 32 ? (size_t)w * 4 : (row_bytes + 3) & ~(size_t)3;
    if (pixel_off + stride * height > dib_len)
        return NULL;

    /* 1. DIB pixels -> tightly packed RGB, top-down (the flip for bottom-up
     * DIBs happens here, once). The 4th byte is read even at 24bpp: the
     * masks decide which bits matter and BI_BITFIELDS uses all of them. */
    unsigned char *rgb = xmalloc((size_t)w * height * 3);
    for (size_t row = 0; row < height; row++) {
        const unsigned char *line = dib + pixel_off
            + (size_t)(top_down ? row : height - 1 - row) * stride;
        unsigned char *out = rgb + row * (size_t)w * 3;
        for (size_t x = 0; x < (size_t)w; x++, out += 3) {
            size_t px = x * (bpp / 8);
            uint32_t v = (uint32_t)line[px]
                | ((uint32_t)line[px + 1] << 8)
                | ((uint32_t)line[px + 2] << 16)
                | ((uint32_t)line[px + 3] << 24);
            out[0] = (unsigned char)(v >> rsh);
            out[1] = (unsigned char)(v >> gsh);
            out[2] = (unsigned char)(v >> bsh);
        }
    }

    /* 2. downscale to the cap, bilinear, preserving aspect ratio. Center
     * sampling keeps the mapping unbiased; edges clamp instead of wrapping. */
    /* Long-edge cap: vision endpoints downscale past ~1568px themselves and
     * refuse base64 bodies over 5-10MB, so a 4K screenshot used to encode to a
     * ~25MB PNG (a ~33MB request: rejected, or 2-3x the tokens a 1568px render
     * costs). Pay the pixels once, here, at bilinear quality. */
    int64_t cap = env_i64("KK_IMG_MAX_EDGE", 1, 1568);
    int64_t long_edge = (int64_t)w > (int64_t)height ? w : (int64_t)height;
    if (cap >= 64 && long_edge > cap) {
        double f = (double)cap / (double)long_edge;
        size_t sw = (size_t)((double)w * f + 0.5);
        size_t sh = (size_t)((double)height * f + 0.5);
        if (sw < 1)
            sw = 1;
        if (sh < 1)
            sh = 1;
        unsigned char *small = xmalloc(sw * sh * 3);
        for (size_t y = 0; y < sh; y++) {
            double sy = ((double)y + 0.5) * (double)height / (double)sh - 0.5;
            size_t y0;
            double fy;
            if (sy <= 0.0) {
                y0 = 0;
                fy = 0.0;
            } else {
                y0 = (size_t)sy;
                if (y0 >= height)
                    y0 = height - 1;
                fy = sy - (double)y0;
            }
            size_t y1 = y0 + 1 < height ? y0 + 1 : y0;
            for (size_t x = 0; x < sw; x++) {
                double sx = ((double)x + 0.5) * (double)w / (double)sw - 0.5;
                size_t x0;
                double fx;
                if (sx <= 0.0) {
                    x0 = 0;
                    fx = 0.0;
                } else {
                    x0 = (size_t)sx;
                    if (x0 >= (size_t)w)
                        x0 = (size_t)w - 1;
                    fx = sx - (double)x0;
                }
                size_t x1 = x0 + 1 < (size_t)w ? x0 + 1 : x0;
                const unsigned char *p00 = rgb + (y0 * (size_t)w + x0) * 3;
                const unsigned char *p01 = rgb + (y0 * (size_t)w + x1) * 3;
                const unsigned char *p10 = rgb + (y1 * (size_t)w + x0) * 3;
                const unsigned char *p11 = rgb + (y1 * (size_t)w + x1) * 3;
                unsigned char *o = small + (y * sw + x) * 3;
                for (int c = 0; c < 3; c++) {
                    double top = (double)p00[c] * (1.0 - fx)
                               + (double)p01[c] * fx;
                    double bot = (double)p10[c] * (1.0 - fx)
                               + (double)p11[c] * fx;
                    o[c] = (unsigned char)(top * (1.0 - fy) + bot * fy + 0.5);
                }
            }
        }
        free(rgb);
        rgb = small;
        w = (int)sw;
        height = sh;
    }

    /* 3. PNG scanlines: filter byte 0 per row, then RGB triplets */
    row_bytes = (size_t)w * 3;
    size_t raw_len = height * (1 + row_bytes);
    unsigned char *raw = xmalloc(raw_len);
    for (size_t row = 0; row < height; row++) {
        unsigned char *out = raw + row * (1 + row_bytes);
        *out++ = 0; /* filter: none */
        memcpy(out, rgb + row * row_bytes, row_bytes);
    }
    free(rgb);

    /* zlib stream: 78 01 + stored deflate blocks over raw + adler32 */
    size_t blocks = (raw_len + 65534) / 65535;
    size_t zlen = 2 + raw_len + blocks * 5 + 4;
    unsigned char *z = xmalloc(zlen);
    z[0] = 0x78;
    z[1] = 0x01;
    size_t zo = 2, ro = 0;
    while (ro < raw_len) {
        size_t block = raw_len - ro < 65535 ? raw_len - ro : 65535;
        z[zo] = (unsigned char)(ro + block >= raw_len ? 1 : 0);
        z[zo + 1] = (unsigned char)block;
        z[zo + 2] = (unsigned char)(block >> 8);
        z[zo + 3] = (unsigned char)(unsigned char)~block;
        z[zo + 4] = (unsigned char)(~block >> 8);
        memcpy(z + zo + 5, raw + ro, block);
        zo += 5 + block;
        ro += block;
    }
    uint32_t adler = png_adler32(raw, raw_len);
    png_put_u32be(z + zo, adler);
    zo += 4;
    free(raw);

    /* PNG assembly: signature + IHDR + IDAT + IEND */
    size_t png_len = 8 + 25 + (12 + zlen) + 12;
    unsigned char *png = xmalloc(png_len);
    static const unsigned char SIGNATURE[8]
        = { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n' };
    memcpy(png, SIGNATURE, 8);
    unsigned char ihdr[13];
    png_put_u32be(ihdr, (uint32_t)w);
    png_put_u32be(ihdr + 4, (uint32_t)height);
    ihdr[8] = 8; /* bit depth */
    ihdr[9] = 2; /* color type: truecolor RGB */
    ihdr[10] = ihdr[11] = ihdr[12] = 0;
    png_chunk(png + 8, 13, "IHDR", ihdr);
    png_chunk(png + 33, (uint32_t)zlen, "IDAT", z);
    png_chunk(png + 33 + 12 + zlen, 0, "IEND", NULL);
    free(z);
    *out_len = png_len;
    return png;
}

/* Dump the clipboard image (if any) to a PNG file in the temp dir.
 * Returns 0 on success; the caller inserts the path into the draft and
 * attach_user_images ships it with the message. */
static int clipboard_image_png(char *path, size_t cap)
{
    unsigned char *dib = NULL, *png = NULL;
    size_t dib_len = 0, png_len = 0;
    int ok = -1;
    if (!OpenClipboard(NULL))
        return -1;
    HANDLE h = GetClipboardData(CF_DIBV5);
    if (!h)
        h = GetClipboardData(CF_DIB);
    if (h) {
        dib = (unsigned char *)GlobalLock(h);
        if (dib) {
            dib_len = GlobalSize(h);
            png = dib_to_png(dib, dib_len, &png_len);
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    if (!png)
        return -1;

    char tmp[MAX_PATH];
    if (GetTempPathA((DWORD)cap, tmp)) {
        static unsigned seq;
        snprintf(path, cap, "%skk-clip-%lu-%u.png", tmp,
                 (unsigned long)GetCurrentProcessId(), ++seq);
        HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD wrote = 0;
            WriteFile(f, png, (DWORD)png_len, &wrote, NULL);
            CloseHandle(f);
            ok = wrote == png_len ? 0 : -1;
            if (ok != 0)
                DeleteFileA(path);
        }
    }
    free(png);
    return ok;
}

/* Scan a user message's text for image file paths (drag & drop inserts
 * quoted paths, the clipboard helper inserts plain ones, users type
 * them) and attach up to 4 to the message. Returns the count. */
static int attach_user_images(struct message *m, const char *text)
{
    int attached = 0;
    const char *p = text;
    while (*p && attached < 4) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'
               || *p == '"')
            p++;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r'
               && *p != '"')
            p++;
        const char *end = p;
        while (end > start && (end[-1] == '"' || end[-1] == '\r'))
            end--;
        size_t n = (size_t)(end - start);
        if (n == 0 || n >= MAX_PATH)
            continue;
        /* extension filter first: a plain sentence opens every word as
         * a file otherwise */
        char path[MAX_PATH];
        memcpy(path, start, n);
        path[n] = '\0';
        const char *mime = NULL;
        size_t keep = n; /* token bytes that are the actual file path */
        const char *dot = strrchr(path, '.');
        if (dot) {
            for (size_t k = 0; k < sizeof known_image_exts
                                     / sizeof known_image_exts[0];
                 k++) {
                if (_stricmp(dot, known_image_exts[k].ext) == 0) {
                    mime = known_image_exts[k].mime;
                    break;
                }
            }
        }
        if (!mime) {
            /* a pasted path followed immediately by typed text
             * ("...x.png画一下这个"): try the prefix ending at a known
             * extension before giving up on the token */
            size_t best = 0;
            for (size_t i = 0; i < n; i++) {
                for (size_t k = 0;
                     k < sizeof known_image_exts / sizeof known_image_exts[0];
                     k++) {
                    size_t el = strlen(known_image_exts[k].ext);
                    if (i + el > best && i + el <= n
                        && _strnicmp(path + i, known_image_exts[k].ext,
                                     el) == 0) {
                        best = i + el;
                        mime = known_image_exts[k].mime;
                    }
                }
            }
            keep = best;
        }
        if (!mime || !keep)
            continue;
        struct str ps = { path, keep };
        size_t len = 0;
        char *data = file_read_all(ps, &len);
        if (!data)
            continue;
        /* magic bytes confirm what the extension claimed */
        const char *real = image_mime_of(ps, data, len);
        if (real) {
            /* a file path cannot be decoded here (no inflate), so the guard
             * refuses only what the endpoint refuses for certain: base64
             * past the byte cap, or a dimension past the documented max.
             * Anything smaller attaches as-is — the endpoint downscales it. */
            int iw = 0, ih = 0;
            /* a file path cannot be re-encoded here (no inflate), so refuse
             * only what the endpoint refuses for certain, and say so before
             * spending a round on a guaranteed rejection */
            int64_t maxb = env_i64("KK_IMG_MAX_BYTES", 1, 8 << 20);
            int over_bytes = maxb >= 1024
                             && (int64_t)(len / 3 * 4 + 64) > maxb;
            int over_dims = image_dims_of(data, len, real, &iw, &ih) == 0
                            && (iw > 8000 || ih > 8000);
            if (over_bytes || over_dims) {
                if (over_dims)
                    out_printf(vt_or("\x1b[33m⚠\x1b[0m 图片 %.*s 为 %dx%d，"
                                     "超过端点 8000px 尺寸上限，未附带上传\r\n",
                                     "⚠ 图片 %.*s 为 %dx%d，超过端点 8000px "
                                     "尺寸上限，未附带上传\r\n"),
                               (int)keep, path, iw, ih);
                else
                    out_printf(vt_or("\x1b[33m⚠\x1b[0m 图片 %.*s 约 %.1fMB，"
                                     "base64 后超过 %lldMB 上限，未附带上传"
                                     "（请先压缩或缩小）\r\n",
                                     "⚠ 图片 %.*s 约 %.1fMB，base64 后超过 "
                                     "%lldMB 上限，未附带上传（请先压缩或"
                                     "缩小）\r\n"),
                               (int)keep, path, (double)len / 1048576.0,
                               (long long)(maxb / 1048576));
                free(data);
                continue;
            }
            struct image_part part = { xstrdup(real), b64_encode(data, len) };
            if (part.mime && part.b64) {
                DA_PUSH(m->images, part);
                attached++;
            } else {
                free(part.mime);
                free(part.b64);
            }
        }
        free(data);
    }
    return attached;
}

/* Detect an image by extension AND magic bytes; NULL when not one of
 * the four formats vision models commonly accept. */
static const char *image_mime_of(struct str path, const char *data,
                                 size_t len)
{
    const char *dot = mem_rfind(path.p, path.n, '.');
    if (!dot)
        return NULL;
    size_t elen = (size_t)(path.p + path.n - dot);
    char ext[8]; /* extensions are 3-5 bytes; a longer tail is not one */
    if (elen >= sizeof ext)
        return NULL;
    memcpy(ext, dot, elen);
    ext[elen] = '\0';
    for (size_t i = 0; i < sizeof known_image_exts / sizeof known_image_exts[0];
         i++) {
        if (_stricmp(ext, known_image_exts[i].ext) != 0)
            continue;
        if (len < 12
            || memcmp(data, known_image_exts[i].magic,
                      known_image_exts[i].magic_len) != 0)
            continue;
        if (known_image_exts[i].webp && memcmp(data + 8, "WEBP", 4) != 0)
            continue;
        return known_image_exts[i].mime;
    }
    return NULL;
}

/* "%6zu| " by hand: read walks every line, and the printf round-trip
 * (measure + write) per line is pure overhead. dst holds >=28 bytes. */
static size_t read_line_prefix(char *dst, size_t line_no)
{
    char num[24];
    size_t nn = 0, v = line_no;
    do {
        num[nn++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    size_t o = 0;
    for (size_t pad = nn < 6 ? 6 - nn : 0; pad; pad--)
        dst[o++] = ' ';
    while (nn)
        dst[o++] = num[--nn];
    dst[o++] = '|';
    dst[o++] = ' ';
    return o;
}

/* One read result is capped at this many bytes whatever `limit` says. A page
 * of `limit` lines, each already capped at KK_LINE_COLS, reaches 800KB on a
 * wide-line file — ~200k tokens in a single tool result, which the model then
 * re-pays on every round of the turn and usually reads a fraction of. 64KB
 * passes any ordinary source file whole (roughly 1300 lines) and bounds the
 * pathological case by 12x; the trailer names the exact line to continue at,
 * so paging costs one extra round instead of a 12x larger bill forever. */
#define READ_PAGE_BYTES (64 * 1024)

/* Format lines offset..offset+limit of one buffer, numbering as it goes. Its
 * own function because the per-line work is three calls, and inside the big
 * tool_read they do not all inline: the same loop measured in a small function
 * ran at half the cost. *trunc_out reports that the byte budget (not the line
 * limit) is what stopped the page. */
static void read_page(struct buf *out, const char *data, size_t len,
                      size_t offset, size_t limit, size_t max_bytes,
                      size_t *emitted_out, size_t *last_out, int *trunc_out)
{
    size_t line_no = 0, emitted = 0, last = 0, bytes = 0;
    int trunc = 0;
    const char *p = data, *end = data + len;
    while (p < end && emitted < limit) {
        line_no++;
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (line_no >= offset) {
            if (bytes >= max_bytes) {
                trunc = 1;
                break; /* the budget, not the page limit, stops here */
            }
            size_t before = out->len;
            char pre[28];
            size_t pn = read_line_prefix(pre, line_no);
            buf_append_line_capped_pfx(out, pre, pn, p, llen);
            bytes += out->len - before;
            emitted++;
            last = line_no;
        }
        p = nl ? nl + 1 : end;
    }
    *emitted_out = emitted;
    *last_out = last;
    *trunc_out = trunc;
}

/* Read a whole file and answer, from the same open, whether somebody else is
 * holding it. dwShareMode 0 *is* the lock test: if the open succeeds nobody
 * else has the file, and ERROR_SHARING_VIOLATION means they do. */
static char *file_read_excl(struct str path, size_t *out_len, int *locked,
                            unsigned long long *too_big_at)
{
    return file_slurp(path, out_len, locked, too_big_at, FILE_READ_CAP, 0);
}

static char *tool_read(const struct jnode *args, struct tool_img *img)
{
    struct args a;
    args_init(&a, args);
    char *result = NULL;
    struct str path = args_get(&a, "path");
    char *data = NULL;
    struct buf out = BUF_INIT;
    if (!path.n) {
        result = xstrdup("error: read requires a path");
        goto cleanup;
    }
    int64_t offset = args_int(args, "offset", 1);
    int64_t limit = args_int(args, "limit", 2000);
    if (offset < 1)
        offset = 1;
    if (limit < 1)
        limit = 2000; /* the emit compare casts to size_t, so a negative
                       * limit would wrap into a huge cap: an omitted or
                       * non-positive limit means the default, never
                       * "everything" */

    /* refuse sizes file_read_excl refuses, but with an honest message: a
     * silent "cannot read" on a file that plainly exists sends the model
     * chasing ghosts. The size comes back from the read itself — no extra
     * attribute syscall. */
    size_t len = 0;
    int locked = 0;
    unsigned long long too_big = 0;
    data = file_read_excl(path, &len, &locked, &too_big);
    if (!data) {
        if (too_big)
            result = xasprintf("error: '%.*s' is %llu MB — too large to "
                               "read whole; slice it with bash "
                               "(Get-Content -TotalCount / "
                               "Select-Object -Skip)",
                               (int)path.n, path.p,
                               too_big / (1024 * 1024));
        else if (locked)
            result = xstrdup("error: file is locked by another process");
        else
            result = xasprintf("error: cannot read '%.*s'", (int)path.n,
                               path.p);
        goto cleanup;
    }
    /* image attachment: detected by extension AND magic bytes, shipped
     * to the tool-result message as base64 for vision models */
    const char *mime = image_mime_of(path, data, len);
    if (mime) {
        img->b64 = b64_encode(data, len);
        img->mime = xstrdup(mime);
        buf_appendf(&out, "[image] %.*s (%s, %zu bytes) attached\r\n",
                    (int)path.n, path.p, mime, len);
        result = buf_detach(&out);
        goto cleanup;
    }
    /* One vector pass answers all three: is this binary, can a transcode even
     * be needed, and how many lines the file has. */
    struct text_scan ts = scan_text(data, len);
    if (ts.control) {
        result = xasprintf("error: '%.*s' is a binary file (%zu bytes); "
                           "use bash to inspect it", (int)path.n, path.p, len);
        goto cleanup;
    }
    /* invalid UTF-8: assume the console codepage (GBK on zh-CN) and
     * transcode so the model sees real text. Pure ASCII is valid UTF-8 by
     * construction, so the scan's answer skips the OS validator outright —
     * over a several-hundred-KB file it cost more than the read. */
    if (!ts.ascii) {
        size_t before = len;
        transcode_to_utf8(&data, &len);
        if (len != before)
            ts = scan_text(data, len); /* the bytes were rewritten: recount */
    }
    /* Lines past the page are never formatted but are still counted, from the
     * scan: the model is told the file's full line count instead of being left
     * to guess, without a second walk over the bytes it will not see. */
    size_t emitted = 0, last = 0;
    int capped = 0;
    read_page(&out, data, len, (size_t)offset, (size_t)limit,
              (size_t)env_i64("KK_READ_MAX_BYTES", 1024, READ_PAGE_BYTES),
              &emitted, &last, &capped);
    if (ts.lines == 0)
        buf_appends(&out, "(empty file)\n");
    else if (emitted == 0)
        buf_appendf(&out, "[offset %zu is beyond end of file: %zu lines]\n",
                    (size_t)offset, ts.lines);
    else if (last < ts.lines && (emitted == (size_t)limit || capped))
        buf_appendf(&out, "[showing lines %zu-%zu of %zu; "
                          "continue with offset %zu]\n",
                    (size_t)offset, last, ts.lines, last + 1);
    result = buf_detach(&out);

cleanup:
    buf_free(&out);
    free(data);
    buf_free(&a.b);
    return result;
}

/* --- write --------------------------------------------------------------- */

/* The diff echo exists so the model can confirm the replacement landed —
 * it is NOT content delivery: a 100KB file rewrite would otherwise ship
 * ~25k tokens of text the model generated itself straight back to it as
 * the tool result. Small edits (the norm) print whole; big ones show the
 * head and the size, and the file is one read away. */
#define DIFF_ECHO_MAX 500
static void append_diff_side(struct buf *msg, char sign, struct str s)
{
    buf_appendf(msg, "  %c ", sign);
    if (s.n <= DIFF_ECHO_MAX) {
        buf_append_n(msg, s.p, s.n);
    } else {
        buf_append_n(msg, s.p, DIFF_ECHO_MAX);
        buf_appendf(msg, "\xE2\x80\xA6[%zu bytes total]", s.n); /* … */
    }
    buf_appendc(msg, '\n');
}

/* Append s to out with \r inserted before every bare \n: shapes old_string
 * and the replacement to a CRLF file when a bare-\n form failed to match. */
static void crlf_fix(struct str s, struct buf *out)
{
    for (size_t k = 0; k < s.n; k++) {
        if (s.p[k] == '\n' && (k == 0 || s.p[k - 1] != '\r'))
            buf_appendc(out, '\r');
        buf_appendc(out, s.p[k]);
    }
}

static char *tool_write(const struct jnode *args, struct tool_img *img_)
{
    (void)img_; /* only read attaches images */
    struct args a;
    args_init(&a, args);
    struct str path = args_get(&a, "path");
    struct str content = args_get(&a, "content");
    struct str old_s = args_get(&a, "old_string");
    struct jnode *ra = jobj_get(args, "replace_all");
    int replace_all = ra && ra->tag == J_TRUE;
    char *result = NULL;
    char *data = NULL;
    struct buf out = BUF_INIT;
    struct buf crlf_old = BUF_INIT, crlf_new = BUF_INIT;

    if (!path.n || !args_has(args, "content")) {
        result = xstrdup("error: write requires path and content");
        goto cleanup;
    }
    if (!args_has(args, "old_string")) {
        /* create or overwrite the whole file */
        if (file_locked(path)) {
            result = xstrdup("error: file is locked by another process");
            goto cleanup;
        }
        if (file_write_all(path, content.p, content.n) != 0) {
            result = xasprintf("error: cannot write '%.*s'", (int)path.n,
                               path.p);
            goto cleanup;
        }
        fff_note_write();
        result = xasprintf("wrote %zu bytes to %.*s", content.n, (int)path.n,
                           path.p);
        goto cleanup;
    }
    /* precise replace: old_string must appear exactly once unless
     * replace_all; content becomes the replacement text. An empty
     * old_string would make the match loop step zero bytes —
     * a hang — so it is rejected outright. */
    if (!old_s.n) {
        result = xstrdup("error: old_string must not be empty; omit it "
                         "to overwrite the whole file");
        goto cleanup;
    }
    static const char cut_marker[] = "…[line truncated]";
    if (mem_find(old_s.p, old_s.n, cut_marker, sizeof cut_marker - 1)) {
        /* the model copied a read line that was cut at KK_LINE_COLS: it
         * can never match the file, so say so instead of failing with a
         * bare not-found */
        result = xstrdup("error: old_string contains a …[line truncated] "
                         "marker — that line was cut by the read tool and "
                         "cannot match the file; fetch the full line with "
                         "bash (Get-Content + Select-Object -Index)");
        goto cleanup;
    }
    /* One exclusive open answers both the lock probe and the read, as in
     * tool_read. A sharing violation is the lock; any other failure is
     * the unreadable file; a missing file is neither. */
    size_t len = 0;
    int locked = 0;
    data = file_read_excl(path, &len, &locked, NULL);
    if (!data) {
        result = locked
                     ? xstrdup("error: file is locked by another process")
                     : xasprintf("error: cannot read '%.*s'", (int)path.n,
                                 path.p);
        goto cleanup;
    }
    /* invalid UTF-8 on disk (GBK etc.): transcode in memory so old_string
     * matching works; the file is written back as UTF-8 */
    transcode_to_utf8(&data, &len);

    struct str oldv = old_s, newv = content;
    size_t count = mem_count(data, len, oldv.p, oldv.n);
    /* CRLF tolerance: the read output shows lines without their \r, so a
     * multi-line old_string arrives with bare \n — retry against the file's
     * CRLF before giving up; the replacement text gets the same endings */
    if (count == 0 && mem_find(data, len, "\r\n", 2)
        && memchr(old_s.p, '\n', old_s.n)) {
        crlf_fix(old_s, &crlf_old);
        crlf_fix(content, &crlf_new);
        count = mem_count(data, len, crlf_old.p, crlf_old.len);
        if (count) {
            oldv = (struct str){ crlf_old.p, crlf_old.len };
            newv = (struct str){ crlf_new.p, crlf_new.len };
        }
    }
    if (count == 0) {
        result = xasprintf("error: old_string not found in %.*s", (int)path.n,
                           path.p);
        goto cleanup;
    }
    if (count > 1 && !replace_all) {
        result = xasprintf("error: old_string appears %zu times in %.*s; "
                           "add surrounding context to make it unique, "
                           "or set replace_all", count, (int)path.n, path.p);
        goto cleanup;
    }
    size_t at = 0;
    for (;;) {
        char *hit = mem_find(data + at, len - at, oldv.p, oldv.n);
        if (!hit) {
            buf_append_n(&out, data + at, len - at); /* trailing remainder */
            break;
        }
        size_t off = (size_t)(hit - data);
        buf_append_n(&out, data + at, off - at);
        buf_append_n(&out, newv.p, newv.n);
        at = off + oldv.n;
        if (at >= len)
            break; /* replaced up to the end */
        if (!replace_all) {
            buf_append_n(&out, data + at, len - at); /* keep the tail */
            break;
        }
    }
    int rc = file_write_all(path, out.p, out.len);
    if (rc == 0 && fff_ok && fff_inst)
        fff_note_write(); /* refresh the index */
    /* compact diff: show what changed for the user and the model */
    if (rc == 0) {
        struct buf msg = BUF_INIT;
        buf_appendf(&msg, "edited %.*s (%zu replacement%s)\n", (int)path.n,
                    path.p, count, count == 1 ? "" : "s");
        append_diff_side(&msg, '-', oldv);
        append_diff_side(&msg, '+', newv);
        result = buf_detach(&msg);
    } else {
        result = xasprintf("error: cannot write '%.*s'", (int)path.n, path.p);
    }

cleanup:
    buf_free(&out);
    free(data);
    buf_free(&crlf_old);
    buf_free(&crlf_new);
    buf_free(&a.b);
    return result;
}

/* --- bash ---------------------------------------------------------------- */

/* Base64 (for PowerShell -EncodedCommand). Returns heap string. */
/* Output length of b64_encode for n input bytes — the encoder's own rule, so
 * a caller that needs the size never re-scans the payload to count it. */
static size_t b64_out_len(size_t n)
{
    return ((n + 2) / 3) * 4;
}

static char *b64_encode(const char *data, size_t n)
{
    /* 12-bit lookup: two output characters per entry, so a full 3-byte
     * group is two lookups + one 32-bit store. Image attach pushes
     * tens of MB through here (a 4K screenshot encodes to ~33MB). */
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static uint32_t lut[4096];
    static int lut_ready;
    if (!lut_ready) {
        for (int v = 0; v < 4096; v++)
            lut[v] = (uint32_t)(unsigned char)tbl[(v >> 6) & 63]
                | ((uint32_t)(unsigned char)tbl[v & 63] << 8);
        lut_ready = 1;
    }
    size_t out_n = b64_out_len(n);
    char *out = xmalloc(out_n + 1);
    size_t o = 0, i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)(unsigned char)data[i] << 16
            | (uint32_t)(unsigned char)data[i + 1] << 8
            | (uint32_t)(unsigned char)data[i + 2];
        *(uint32_t *)(out + o) =
            lut[(v >> 12) & 4095] | (lut[v & 4095] << 16);
        o += 4;
    }
    if (i < n) {
        uint32_t v = (uint32_t)(unsigned char)data[i] << 16;
        if (i + 1 < n)
            v |= (uint32_t)(unsigned char)data[i + 1] << 8;
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = i + 1 < n ? tbl[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

/* --- persistent PowerShell session ---------------------------------------- */

/* One PowerShell process serves every bash call: it reads one base64 line per
 * call ("guid\ncommand"), invokes it, and answers with a per-call completion
 * marker "<<<KK-DONE:guid:exit>>>". This skips the ~1.1s process start each
 * per-call spawn paid, and lets the working directory and environment carry
 * over. The spawn is prewarmed on a background thread at startup; g_ps_lock
 * arbitrates that spawn against the first tool call reaching shell_run. The
 * call itself is synchronous and runs on the agent thread only. */

static HANDLE g_ps_process; /* the long-lived powershell.exe */
static HANDLE g_ps_job;     /* KILL_ON_JOB_CLOSE sweeps the whole tree */
static HANDLE g_ps_stdin_w; /* we write one base64 line per call */
static HANDLE g_ps_out_r;   /* merged stdout+stderr of the session */
static char g_ps_guid[16];  /* marker id of the call in flight */
static unsigned g_ps_seq;
static SRWLOCK g_ps_lock = SRWLOCK_INIT;

/* Kill the session: the tree dies with the job, a fresh shell serves
 * the next call. */
static void ps_kill(void)
{
    AcquireSRWLockExclusive(&g_ps_lock);
    if (g_ps_job)
        TerminateJobObject(g_ps_job, 1);
    if (g_ps_stdin_w) {
        CloseHandle(g_ps_stdin_w);
        g_ps_stdin_w = NULL;
    }
    if (g_ps_out_r) {
        CloseHandle(g_ps_out_r);
        g_ps_out_r = NULL;
    }
    if (g_ps_process) {
        CloseHandle(g_ps_process);
        g_ps_process = NULL;
    }
    if (g_ps_job) {
        CloseHandle(g_ps_job);
        g_ps_job = NULL;
    }
    ReleaseSRWLockExclusive(&g_ps_lock);
}

/* Ensure the session exists: the startup prewarm may still be spawning
 * when the first tool call lands, so the check takes the lock. */
static int ps_spawn(void);
static int ps_ensure(void)
{
    AcquireSRWLockExclusive(&g_ps_lock);
    int rc = g_ps_process ? 0 : ps_spawn();
    ReleaseSRWLockExclusive(&g_ps_lock);
    return rc;
}

/* Startup prewarm: pay the PowerShell cold start while the user is
 * still typing / the model is still thinking. */
static DWORD WINAPI ps_prewarm(LPVOID arg)
{
    (void)arg;
    ps_ensure();
    return 0;
}

static int ps_spawn(void)
{
    /* The loop protocol: one base64("guid\ncommand") line in, command output
     * plus a marker line out. Base64 keeps every command quote-safe, exactly
     * like -EncodedCommand does. 6>&1 folds the information stream
     * (Write-Host et al.) back into the pipeline: with piped handles and no
     * console, PS serializes host writes as CLIXML XML on stderr instead of
     * plain text. EAP=Stop routes cmdlet errors into the catch as plain text
     * — the redirected error stream would otherwise serialize as CLIXML and
     * flush lazily across calls. The output AND the marker go through
     * [Console]::Out with an explicit flush, NOT through Write-Output: the
     * host's redirected-output writer holds formatted output indefinitely, so
     * a quiet command's marker would only reach the pipe when the NEXT
     * command arrives, deadlocking the wait-for-marker protocol. */
    static const char *loop =
        "$ProgressPreference = 'SilentlyContinue'\n"
        "$ErrorActionPreference = 'Stop'\n"
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
        "while ($true) {\n"
        "  $line = [Console]::In.ReadLine()\n"
        "  if ($null -eq $line) { break }\n"
        "  try {\n"
        "    $dec = [Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String($line.Trim()))\n"
        "    $ix = $dec.IndexOf([char]10)\n"
        "    if ($ix -lt 0) { continue }\n"
        "    $guid = $dec.Substring(0, $ix)\n"
        "    $cmd = $dec.Substring($ix + 1)\n"
        "    $global:LASTEXITCODE = 0\n"
        "    Invoke-Expression $cmd 6>&1 | Out-String -Stream | "
        "ForEach-Object { [Console]::Out.WriteLine($_) }\n"
        "  } catch { $global:LASTEXITCODE = 1; "
        "$_ | Out-String | ForEach-Object "
        "{ [Console]::Out.WriteLine($_) } }\n"
        "  [Console]::Out.WriteLine((\"<<<KK-DONE:{0}:{1}>>>\" -f $guid, "
        "$global:LASTEXITCODE))\n"
        "  [Console]::Out.Flush()\n"
        "}\n";

    int fn = MultiByteToWideChar(CP_UTF8, 0, loop, -1, NULL, 0);
    wchar_t *wfull = xmalloc((size_t)fn * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, loop, -1, wfull, fn);
    char *raw = xmalloc((size_t)fn * 2);
    memcpy(raw, wfull, (size_t)fn * 2);
    free(wfull);
    char *encoded = b64_encode(raw, (size_t)fn * 2 - 2);
    free(raw);
    char *line = xasprintf("powershell.exe -NoProfile -NonInteractive "
                           "-EncodedCommand %s",
                           encoded);
    free(encoded);
    wchar_t *cmdline = w_from_utf8(line);
    free(line);

    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE in_r = NULL, in_w = NULL, out_r = NULL, out_w = NULL;
    int result = -1;
    if (!CreatePipe(&in_r, &in_w, &sa, 0)
        || !CreatePipe(&out_r, &out_w, &sa, 0))
        goto fail;

    {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = in_r;
        si.hStdOutput = out_w;
        si.hStdError = out_w;
        BOOL ok = CreateProcessW(NULL, cmdline, NULL, NULL, TRUE,
                                 CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL,
                                 NULL, &si, &pi);
        if (!ok)
            goto fail;
        CloseHandle(in_r);
        CloseHandle(out_w);

        g_ps_job = CreateJobObjectW(NULL, NULL);
        if (g_ps_job) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim;
            memset(&lim, 0, sizeof lim);
            lim.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(g_ps_job, JobObjectExtendedLimitInformation,
                                    &lim, sizeof lim);
            AssignProcessToJobObject(g_ps_job, pi.hProcess);
        }
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);

        g_ps_process = pi.hProcess;
        g_ps_stdin_w = in_w;
        g_ps_out_r = out_r;
        result = 0;
        goto done;
    }

fail:
    if (in_r)
        CloseHandle(in_r);
    if (in_w)
        CloseHandle(in_w);
    if (out_r)
        CloseHandle(out_r);
    if (out_w)
        CloseHandle(out_w);

done:
    free(cmdline);
    return result;
}

/* --- CLIXML fallback ------------------------------------------------------ */

/* Windows PowerShell serializes host-class output (cmdlet errors, Write-Host
 * inside a nested powershell.exe) as `#< CLIXML` + an <Objs> document on the
 * merged pipe — with 6>&1 folding the info stream, a cmdlet error exists ONLY
 * in this form. Recover the Error/Message text so the model reads sentences,
 * not markup; the decoded text replaces the document, so model and screen see
 * the same thing. */

/* Four hex digits, or -1. The JSON layer already has this reader. */
static int hex4(const char *s)
{
    size_t i = 0;
    return jhex_quad(s, 4, &i);
}

/* Decode one record's inner text: PowerShell's private-use _xHHHH_
 * escapes plus the XML named entities. */
static void clixml_text(struct buf *out, const char *s, size_t n)
{
    static const struct { const char *ent; char ch; } NAMED[] = {
        {"&lt;", '<'},  {"&gt;", '>'}, {"&quot;", '"'},
        {"&apos;", '\''}, {"&amp;", '&'},
    };
    for (size_t i = 0; i < n;) {
        if (i + 7 <= n && s[i] == '_' && s[i + 1] == 'x'
            && s[i + 6] == '_') {
            int cp = hex4(s + i + 2);
            if (cp >= 0) {
                /* An astral character arrives as two _xHHHH_ escapes
                 * holding one UTF-16 surrogate pair; u8_encode has no
                 * surrogate guard, so fold the pair and floor a stray
                 * half to U+FFFD. */
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    int lo = -1;
                    if (i + 14 <= n && s[i + 7] == '_' && s[i + 8] == 'x'
                        && s[i + 13] == '_')
                        lo = hex4(s + i + 9);
                    if (lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        i += 7;
                    } else {
                        cp = 0xFFFD;
                    }
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    cp = 0xFFFD;
                }
                char tmp[4];
                buf_append_n(out, tmp, u8_encode((uint32_t)cp, tmp));
                i += 7;
                continue;
            }
        }
        if (s[i] == '&') {
            int done = 0;
            for (size_t k = 0; k < 5 && !done; k++) {
                size_t el = strlen(NAMED[k].ent);
                if (i + el <= n && memcmp(s + i, NAMED[k].ent, el) == 0) {
                    buf_appendc(out, NAMED[k].ch);
                    i += el;
                    done = 1;
                }
            }
            if (done)
                continue;
        }
        buf_appendc(out, s[i]);
        i++;
    }
}

static void clixml_decode(struct buf *b)
{
    if (!b->p || b->len < 24 || !strstr(b->p, "<Objs "))
        return;
    struct buf out = BUF_INIT;
    size_t i = 0;
    while (i < b->len) {
        char *doc = strstr(b->p + i, "<Objs ");
        if (!doc) {
            buf_append_n(&out, b->p + i, b->len - i);
            break;
        }
        size_t dpos = (size_t)(doc - b->p);
        /* drop the `#< CLIXML` header line, which always sits on its
         * own line right before the document */
        if (dpos >= 11 && memcmp(b->p + dpos - 11, "#< CLIXML\r\n", 11) == 0)
            dpos -= 11;
        else if (dpos >= 10
                 && memcmp(b->p + dpos - 10, "#< CLIXML\n", 10) == 0)
            dpos -= 10;
        buf_append_n(&out, b->p + i, dpos - i);
        char *close = strstr(doc, "</Objs>");
        if (!close) {
            /* truncated document: keep the raw tail rather than guess */
            buf_append_n(&out, doc, b->len - dpos);
            break;
        }
        char *end = close + 7;
        for (char *s = doc; s < end;) {
            char *tag = strstr(s, "<S ");
            if (!tag || tag >= end)
                break;
            char *gt = strchr(tag, '>');
            char *sc = strstr(tag, "</S>");
            if (!gt || !sc || sc < gt || sc >= end) {
                s = tag + 3;
                continue;
            }
            /* only Error and Message records carry visible text */
            if ((tag + 3 + 9 <= end
                 && memcmp(tag + 3, "S=\"Error\"", 9) == 0)
                || (tag + 3 + 11 <= end
                    && memcmp(tag + 3, "N=\"Message\"", 11) == 0)) {
                size_t raw = (size_t)(sc - (gt + 1));
                size_t before = out.len;
                clixml_text(&out, gt + 1, raw);
                /* records already end with an escaped CRLF; only pad
                 * the rare one that does not */
                if (!(out.len >= 2 && out.p[out.len - 2] == '\r'
                      && out.p[out.len - 1] == '\n')
                    && out.len > before)
                    buf_appendc(&out, '\n');
            }
            s = sc + 4;
        }
        i = (size_t)(end - b->p);
    }
    buf_free(b);
    *b = out;
}

/* Run a command through the persistent PowerShell session. Returns 0
 * and fills output/exit_code; nonzero when the session cannot spawn. */
static int shell_run(struct str command,
                     long timeout_ms, struct buf *output, int *exit_code)
{
    if (timeout_ms <= 0)
        timeout_ms = 120000;

    for (int attempt = 0; attempt < 2; attempt++) {
        if (ps_ensure() != 0)
            return -1;

        /* one pure-ASCII line: base64 of "guid\ncommand" */
        snprintf(g_ps_guid, sizeof g_ps_guid, "%08x", ++g_ps_seq);
        struct buf line = BUF_INIT;
        buf_appends(&line, g_ps_guid);
        buf_appendc(&line, '\n');
        buf_append_n(&line, command.p, command.n);
        char *b64 = b64_encode(line.p, line.len);
        /* The wire is the base64 plus its CRLF, and the encoder's own rule
         * says how long that is: no re-scan of a command line that can run to
         * 160 KB on the way into the shell. */
        size_t wire_n = b64_out_len(line.len) + 2;
        buf_free(&line);
        char *wire = xasprintf("%s\r\n", b64);
        free(b64);

        DWORD wrote = 0;
        int sent = WriteFile(g_ps_stdin_w, wire, (DWORD)wire_n, &wrote, NULL);
        free(wire);
        if (!sent) {
            /* the session died since the last call; respawn and resend */
            ps_kill();
            continue;
        }
        struct buf out = BUF_INIT;

        /* Read until the marker, EOF, or the deadline; the call's output and
         * the trailing marker line interleave in one pipe. scan_from resumes
         * the marker search after each chunk (the prefix may straddle a
         * boundary), keeping big outputs linear. The deadline sits at the
         * loop TOP: a command that streams forever (ping -t, a dev server)
         * must also time out, not just one that sits silent. */
        size_t at = 0, scan_from = 0;
        /* the marker prefix is stable for this call: build it once, not per
         * pipe chunk */
        char pre[48];
        size_t plen = (size_t)snprintf(pre, sizeof pre, "<<<KK-DONE:%s:",
                                       g_ps_guid);
        int have_marker = 0, dead = 0, cancelled = 0, polls = 0;
        DWORD t0 = GetTickCount();
        for (;;) {
            if (InterlockedCompareExchange(&g_cancel, 0, 0)) {
                /* Ctrl+C: the user must not wait out a hung command */
                cancelled = 1;
                break;
            }
            if (GetTickCount() - t0 > (DWORD)timeout_ms)
                break; /* deadline */
            DWORD avail = 0;
            if (!PeekNamedPipe(g_ps_out_r, NULL, 0, NULL, &avail, NULL)) {
                dead = 1; /* pipe broke: the session is gone */
                break;
            }
            if (avail > 0) {
                char tmp[32768];
                DWORD got = 0;
                if (!ReadFile(g_ps_out_r, tmp,
                              avail > sizeof tmp ? sizeof tmp : avail, &got,
                              NULL)
                    || got == 0) {
                    dead = 1;
                    break;
                }
                buf_append_n(&out, tmp, got);
                if (out.len > 8 * 1024 * 1024) {
                    dead = 1; /* refuse unbounded output */
                    break;
                }
                char *hit = mem_find(out.p + scan_from, out.len - scan_from,
                                     pre, plen);
                if (hit) {
                    at = (size_t)(hit - out.p);
                    have_marker = 1;
                    break;
                }
                scan_from = out.len > plen ? out.len - (plen - 1) : 0;
                continue;
            }
            /* The status line (spinner thread) shows the tool label and
             * elapsed time; the poll loop here only watches the pipe. Back off
             * after ~100 ms: a flat 2 ms cadence costs ~7x the CPU on a
             * command that produces nothing for a second. Forty 2 ms polls
             * cover the calls that answer quickly; anything still silent after
             * that is polled at 10 ms. */
            kk_nap(polls < 40 ? 2 : 10, NULL);
            polls++;
        }

        if (have_marker) {
            /* completed: the session stays up for the next call */
            *exit_code = atoi(out.p + at + plen + 1);
            /* stderr (CLIXML) often trails the marker line in the merged pipe;
             * wait briefly for it — but only when stderr actually sent
             * something, so clean calls pay nothing */
            if (strstr(out.p, "#< CLIXML")) {
                /* A deadline in ms, not a poll count: what the loop is really
                 * about is silence after the last byte. */
                DWORD quiet_since = GetTickCount();
                for (;;) {
                    DWORD avail = 0;
                    if (!PeekNamedPipe(g_ps_out_r, NULL, 0, NULL, &avail,
                                       NULL))
                        break;
                    if (avail > 0) {
                        char tmp[32768];
                        DWORD got = 0;
                        if (ReadFile(g_ps_out_r, tmp,
                                     avail > sizeof tmp ? sizeof tmp : avail,
                                     &got, NULL)
                            && got > 0)
                            buf_append_n(&out, tmp, got);
                        quiet_since = GetTickCount();
                        continue;
                    }
                    if (GetTickCount() - quiet_since >= 120)
                        break;
                    kk_nap(2, NULL);
                }
            }
            /* drop the marker line itself from the middle of the stream —
             * in place, then hand the buffer to the caller: a command that
             * returned megabytes pays no second copy of them */
            char *lend = strchr(out.p + at, '\n');
            size_t llen = lend ? (size_t)(lend - (out.p + at)) + 1
                               : out.len - at;
            if (llen) {
                memmove(out.p + at, out.p + at + llen, out.len - at - llen);
                out.len -= llen;
            }
            out.p[out.len] = '\0';
            buf_free(output);
            *output = out; /* ownership moves; `out` is dead from here */
            out.p = NULL;
            break;
        }
        /* dead, cancelled or timed out: salvage what came back, kill the
         * session; a fresh shell serves the next call */
        if (cancelled || !dead)
            *exit_code = -1; /* killed on ^C or on the deadline */
        else
            *exit_code = 1;  /* the shell exited without a marker */
        buf_reset(output);
        if (out.len) {
            buf_append_n(output, out.p, out.len);
            if (dead) {
                /* the marker line (if any) is not a real exit status */
                char *cut = strstr(output->p, "<<<KK-DONE:");
                if (cut)
                    *cut = '\0';
                output->len = strlen(output->p);
            }
        }
        /* tell the model why the output ends where it does — display ==
         * model view for abnormal ends too */
        if (cancelled)
            buf_appends(output, "\n[cancelled by Ctrl+C]");
        else if (!dead)
            buf_appendf(output, "\n[command timed out after %lus]",
                        (unsigned long)((GetTickCount() - t0) / 1000));
        else
            buf_appends(output, "\n[shell session died]");
        buf_free(&out);
        ps_kill();
        break;
    }

    /* child output: make it valid UTF-8 for the model and the screen */
    transcode_to_utf8(&output->p, &output->len);
    clixml_decode(output);
    return 0;
}

/* --- dispatch ------------------------------------------------------------ */

static char *tool_bash(const struct jnode *args, struct tool_img *img_)
{
    (void)img_; /* only read attaches images */
    struct args a;
    args_init(&a, args);
    struct str command = args_get(&a, "command");
    if (!command.n) {
        buf_free(&a.b);
        return xstrdup("error: bash requires a command");
    }
    long timeout = (long)args_int(args, "timeout_ms", 120000);
    if (timeout > 600000)
        timeout = 600000; /* ten minutes: a hung command must not own
                             the turn past what the user would wait */
    struct buf out = BUF_INIT;
    int exit_code = 0;
    char *result;
    int sret = shell_run(command, timeout, &out, &exit_code);
    if (sret != 0) {
        result = xstrdup("error: failed to spawn shell");
    } else {
        /* cap the display/model view identically */
        size_t cap = 32 * 1024;
        if (out.len > cap) {
            struct buf trimmed = BUF_INIT;
            buf_append_n(&trimmed, out.p, cap / 2);
            buf_appendf(&trimmed,
                        "\n...[output truncated: %zu of %zu bytes "
                        "hidden]...\n",
                        out.len - cap, out.len);
            buf_append_n(&trimmed, out.p + out.len - cap / 2, cap / 2);
            buf_free(&out);
            out = trimmed;
        }
        /* trim blank leading/trailing lines: shells pad. A final
         * line without \n is kept unless it is blank. */
        char *s = out.p;
        char *e = s + out.len;
        while (s < e) {
            char *eol = memchr(s, '\n', (size_t)(e - s));
            size_t llen = (size_t)((eol ? eol : e) - s);
            if (!blank_line(s, llen))
                break;
            s += llen + (eol ? 1 : 0);
        }
        while (e > s) {
            char *sol = e - 1;
            while (sol > s && sol[-1] != '\n')
                sol--;
            size_t llen = (size_t)(e - sol);
            if (e[-1] == '\n')
                llen--;
            if (!blank_line(sol, llen))
                break;
            e = (sol > s && sol[-1] == '\n') ? sol : s;
        }
        if (e <= s)
            result = xasprintf("exit %d\n(no output)", exit_code);
        else
            result = xasprintf("exit %d\n%.*s", exit_code, (int)(e - s), s);
    }
    buf_free(&out);
    buf_free(&a.b);
    return result;
}

static char *tool_execute(const char *name, const struct jnode *args,
                          struct tool_img *img)
{
    const struct tool_spec *ts = tool_lookup(name);
    char *result = ts ? ts->exec(args, img) : NULL;
    if (!result)
        result = ts ? xstrdup("error: tool failed")
                    : xasprintf("error: unknown tool '%s'", name);
    return result;
}

/* --- tool call display (full transparency: everything is shown) ---------- */

static void tool_show_call(const char *name, const char *summary)
{
    if (g_emit_vt)
        out_printf("\x1b[36m● %s\x1b[0m  %s\r\n", name, summary);
    else
        out_printf("* %s  %s\r\n", name, summary);
}

static void tool_show_exit(const char *output)
{
    const char *nl = strchr(output, '\n');
    size_t n = nl ? (size_t)(nl - output) : strlen(output);
    if (n > 63)
        n = 63; /* the status line carries the head of the result only */
    /* print the slice with a precision instead of copying it to a stack
     * buffer first: %.*s needs no terminator */
    if (g_emit_vt)
        out_printf("\x1b[2m  %.*s\x1b[0m\r\n", (int)n, output);
    else
        out_printf("  %.*s\r\n", (int)n, output);
}

static void tool_show_output(const char *output)
{
    /* skip the "exit N" first line; trim blank edges (shells pad); the
     * rest is dim-indented two columns, batched into one console write */
    const char *nl = strchr(output, '\n');
    /* Everything shown here is the *rest* of the output: tool_show_exit
     * already printed the first line. A single-line result — write's
     * "wrote N bytes to path", any error string — has no rest, and
     * falling back to the whole buffer printed that line twice. */
    if (!nl)
        return;
    const char *body = nl + 1;
    const char *end = body + strlen(body);
    while (end > body && (end[-1] == '\n' || end[-1] == '\r'
                          || end[-1] == ' ' || end[-1] == '\t'))
        end--;
    while (body < end) {
        const char *eol = memchr(body, '\n', (size_t)(end - body));
        size_t llen = (size_t)((eol ? eol : end) - body);
        if (llen > 0 && body[llen - 1] == '\r')
            llen--;
        if (!blank_line(body, llen))
            break;
        body += llen + (eol ? 1 : 0);
    }
    if (body >= end)
        return;

    struct buf b = BUF_INIT;
    if (g_emit_vt)
        buf_append_lit(&b, "\x1b[2m");
    buf_append_lit(&b, "  ");
    /* bulk-copy the runs between newlines: a buf_appendc per byte paid a
     * reserve check on every character of every tool output */
    for (const char *c = body; c < end;) {
        const char *eol = memchr(c, '\n', (size_t)(end - c));
        if (!eol) {
            buf_append_n(&b, c, (size_t)(end - c));
            break;
        }
        buf_append_n(&b, c, (size_t)(eol - c));
        if (eol + 1 >= end)
            break;
        buf_append_lit(&b, "\r\n  ");
        c = eol + 1;
    }
    if (g_emit_vt)
        buf_append_lit(&b, "\x1b[0m");
    buf_append_lit(&b, "\r\n");
    out_write(b.p, b.len);
    buf_free(&b);
}
/* ==========================================================================
 * 8. session/config — kv config file + env resolution + shell
 * ========================================================================== */

struct config {
    char *base_url;
    char *api_key;
    char *model;
};

static char *g_appdata_dir;  /* %APPDATA%\kk  — config */
static char *g_localapp_dir; /* %LOCALAPPDATA%\kk — sessions */

static void dirs_init(void)
{
    char *appdata = env_get("APPDATA");
    char *localapp = env_get("LOCALAPPDATA");
    g_appdata_dir = xasprintf("%s\\kk", appdata ? appdata : ".");
    g_localapp_dir = xasprintf("%s\\kk", localapp ? localapp : ".");
    free(appdata);
    free(localapp);
}

/* Read key=value lines. '#' starts a comment. Values may contain '='. */
static void config_read_file(struct config *cfg, const char *path)
{
    size_t n = 0;
    char *text = file_read_all(str_from_c(path), &n);
    if (!text)
        return;

    char *line = text;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        size_t llen = nl ? (size_t)(nl - line) : strlen(line);
        struct str s = { line, llen };
        /* trim \r and spaces */
        while (s.n > 0 && (s.p[s.n - 1] == '\r' || s.p[s.n - 1] == ' '))
            s.n--;
        while (s.n > 0 && *s.p == ' ') {
            s.p++;
            s.n--;
        }
        if (s.n > 0 && *s.p != '#') {
            const char *eq = memchr(s.p, '=', s.n);
            if (eq) {
                struct str key = { s.p, (size_t)(eq - s.p) };
                struct str val = { eq + 1, s.n - (size_t)(eq - s.p) - 1 };
                char *v = str_dupz(val);
                if (str_eqc(key, "base_url") && *v) {
                    free(cfg->base_url);
                    cfg->base_url = v;
                } else if (str_eqc(key, "api_key") && *v) {
                    free(cfg->api_key);
                    cfg->api_key = v;
                } else if (str_eqc(key, "model") && *v) {
                    free(cfg->model);
                    cfg->model = v;
                } else {
                    free(v);
                }
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    free(text);
}

static void config_load(struct config *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    cfg->base_url = xstrdup("https://api.openai.com/v1");

    char *path = xasprintf("%s\\config", g_appdata_dir);
    config_read_file(cfg, path);
    free(path);

    /* environment overrides the file; standard OpenAI names work as fallbacks */
    const struct {
        const char *kk, *fallback;
        char **slot;
    } envs[] = {
        { "KK_BASE_URL", "OPENAI_BASE_URL", &cfg->base_url },
        { "KK_API_KEY", "OPENAI_API_KEY", &cfg->api_key },
        { "KK_MODEL", NULL, &cfg->model },
    };
    for (size_t i = 0; i < sizeof envs / sizeof envs[0]; i++) {
        char *v = env_get(envs[i].kk);
        if (!v && envs[i].fallback)
            v = env_get(envs[i].fallback);
        if (v && *v) {
            free(*envs[i].slot);
            *envs[i].slot = v;
        } else {
            free(v);
        }
    }
}

static void config_free(struct config *cfg)
{
    free(cfg->base_url);
    free(cfg->api_key);
    free(cfg->model);
    free(g_status_model);
    g_status_model = NULL;
}

/* --- session JSONL persistence ----------------------------------------- */

struct session_log {
    HANDLE file;
    char *path;
    struct buf w; /* user-space write buffer: a tool-heavy round logs N+2
                   * records; they reach the file in ONE WriteFile at the
                   * turn's end (or at 64 KB), in order. A crash costs at
                   * most the unflushed turn, never a torn line. */
};

/* Flush the buffered records. Called at turn end, before any blocking wait
 * for input, and on every lifecycle boundary that closes the log. */
static void session_flush(struct session_log *sl)
{
    if (sl->w.len && sl->file) {
        DWORD wrote = 0;
        WriteFile(sl->file, sl->w.p, (DWORD)sl->w.len, &wrote, NULL);
    }
    buf_reset(&sl->w);
}

/* Point %LOCALAPPDATA%\kk\current at the session --continue should reopen:
 * every place a log becomes the active one writes this same pointer. */
static void session_point_current(const char *path)
{
    char *cur = xasprintf("%s\\current", g_localapp_dir);
    file_write_all(str_from_c(cur), path, strlen(path));
    free(cur);
}

/* Open the log on its first record. A launch that never sends a message
 * then leaves no 0-byte session behind, and `current` keeps naming the
 * newest session that actually has content for --continue. */
static void session_touch(struct session_log *sl)
{
    if (sl->file || !sl->path)
        return;
    HANDLE f = CreateFileA(sl->path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return;
    sl->file = f;
    session_point_current(sl->path);
}

static void session_write_line(struct session_log *sl, const char *data,
                               size_t len)
{
    session_touch(sl);
    if (!sl->file)
        return;
    /* the newline rides in the caller's buffer — a record without it glues
     * to the next line and the loader drops both. Contract unchanged; only
     * the syscall count changed: buffered here, flushed once per turn. */
    buf_append_n(&sl->w, data, len);
    if (sl->w.len >= 64 * 1024)
        session_flush(sl);
}

static void session_log_message(struct session_log *sl,
                                const struct message *m)
{
    if (!sl->path)
        return;
    struct buf b = BUF_INIT;
    msg_serialize(&b, m, 0);
    buf_appendc(&b, '\n');
    session_write_line(sl, b.p, b.len);
    buf_free(&b);
}

/* One record per API ROUND, not per user turn: the on-screen `ch` sums the
 * whole turn, so it cannot tell a cold first round from an unstable prefix.
 * cache_tokens is omitted when the endpoint reports none, which keeps the
 * line byte-identical to the old format for those providers. req/shared are
 * the request size and how many leading bytes repeated the previous round —
 * the pair that separates "our prefix moved" from "their cache is cold". */
static void session_log_usage(struct session_log *sl, int64_t prompt,
                              int64_t completion, int64_t cache,
                              int has_cache, size_t req, size_t shared,
                              int has_prev)
{
    if (!sl->path)
        return;
    char cf[32];
    cf[0] = '\0';
    if (has_cache)
        snprintf(cf, sizeof cf, ",\"cache_tokens\":%lld", (long long)cache);
    char rq[64];
    rq[0] = '\0';
    if (has_prev)
        snprintf(rq, sizeof rq, ",\"req\":%zu,\"shared\":%zu", req, shared);
    char line[192];
    int n = snprintf(line, sizeof line,
                     "{\"type\":\"usage\",\"prompt_tokens\":%lld,"
                     "\"completion_tokens\":%lld%s%s}",
                     (long long)prompt, (long long)completion, cf, rq);
    if (n > 0 && n < (int)sizeof line - 1) {
        line[n++] = '\n';
        session_write_line(sl, line, (size_t)n);
    }
}

/* Record a compaction. The log stays append-only: loaders replay the
 * replacement (drop the head down to keep, re-add the summary) so
 * --continue sees exactly the view the model sees. */
static void session_log_compact(struct session_log *sl, size_t keep,
                                const char *summary)
{
    if (!sl->path)
        return;
    struct buf b = BUF_INIT;
    buf_appendf(&b, "{\"type\":\"compact\",\"keep\":%zu,\"summary\":\"",
                keep);
    json_escape_append(&b, summary, strlen(summary));
    buf_appends(&b, "\"}");
    buf_appendc(&b, '\n');
    session_write_line(sl, b.p, b.len);
    buf_free(&b);
}

/* Load a session file's messages into cv. Returns 0 on success. */
static int session_load(const char *path, struct conversation *cv)
{
    size_t len = 0;
    char *data = file_slurp(str_from_c(path), &len, NULL, NULL,
                            SESSION_READ_CAP, 0);
    if (!data)
        return -1;
    struct arena a;
    arena_init(&a, 16 * 1024);
    char *p = data;
    while (*p) {
        char *nl = strchr(p, '\n');
        size_t llen = nl ? (size_t)(nl - p) : strlen(p);
        arena_reset(&a);
        struct jnode *v = json_parse(&a, p, llen);
        if (v && v->tag == J_OBJ) {
            struct jnode *type = jobj_get(v, "type");
            if (type && type->tag == J_STR && str_eqc(type->raw, "message")) {
                char *role = jstr_dupz(jobj_get(v, "role"));
                struct jnode *jc = jobj_get(v, "content");
                char *content = jc && jc->tag == J_STR ? jstr_dupz(jc)
                                                       : NULL;
                struct message *m = conv_add_take(cv, role ? role : "user",
                                                  content);
                free(role);
                struct jnode *calls = jobj_get(v, "tool_calls");
                if (calls && calls->tag == J_ARR) {
                    size_t n = 0;
                    for (struct jnode *c = calls->head; c; c = c->next)
                        n++;
                    m->calls = xcalloc(n, sizeof *m->calls);
                    m->n_calls = n;
                    size_t i = 0;
                    for (struct jnode *c = calls->head; c; c = c->next, i++) {
                        m->calls[i].id = jstr_or(jobj_get(c, "id"), "");
                        m->calls[i].name = jstr_or(jobj_get(c, "name"), "");
                        m->calls[i].args =
                            jstr_or(jobj_get(c, "arguments"), "{}");
                    }
                }
                struct jnode *tcid = jobj_get(v, "tool_call_id");
                if (tcid && tcid->tag == J_STR)
                    m->tool_call_id = jstr_dupz(tcid);
                /* images: new array form + the single-image form the
                 * first image rounds wrote */
                struct jnode *ims = jobj_get(v, "images");
                if (ims && ims->tag == J_ARR) {
                    for (struct jnode *ip = ims->head; ip; ip = ip->next) {
                        struct jnode *pm = jobj_get(ip, "mime");
                        struct jnode *pd = jobj_get(ip, "data");
                        if (pm && pm->tag == J_STR && pd && pd->tag == J_STR) {
                            struct image_part part = { jstr_dupz(pm),
                                                       jstr_dupz(pd) };
                            if (part.mime && part.b64)
                                DA_PUSH(m->images, part);
                            else {
                                free(part.mime);
                                free(part.b64);
                            }
                        }
                    }
                } else {
                    struct jnode *im = jobj_get(v, "image_mime");
                    struct jnode *ib = jobj_get(v, "image_b64");
                    if (im && im->tag == J_STR && ib && ib->tag == J_STR) {
                        struct image_part part = { jstr_dupz(im),
                                                   jstr_dupz(ib) };
                        if (part.mime && part.b64)
                            DA_PUSH(m->images, part);
                        else {
                            free(part.mime);
                            free(part.b64);
                        }
                    }
                }
            } else if (type && type->tag == J_STR
                       && str_eqc(type->raw, "compact")) {
                /* replay the compaction: fold to the kept tail, then
                 * re-add the summary — the model view is reconstructed */
                struct jnode *k = jobj_get(v, "keep");
                struct jnode *s = jobj_get(v, "summary");
                size_t n = cv->msgs.n;
                size_t keep = k && k->tag == J_NUM ? (size_t)jnum_i(k) : 0;
                conv_drop_head(cv, keep < n ? n - keep : 0);
                if (s && s->tag == J_STR) {
                    char *summary = jstr_dupz(s);
                    if (summary)
                        conv_prepend_user(cv, summary);
                }
            }
        }
        p = nl ? nl + 1 : p + llen;
    }
    arena_free(&a);
    free(data);
    return 0;
}

/* Open a new session file (or reopen the latest for --continue). */
static void session_open(struct session_log *sl, int cont,
                         struct conversation *cv)
{
    memset(sl, 0, sizeof *sl);
    CreateDirectoryA(g_localapp_dir, NULL);
    char *dir = xasprintf("%s\\sessions", g_localapp_dir);
    CreateDirectoryA(dir, NULL);
    char *cur = xasprintf("%s\\current", g_localapp_dir);

    if (cont) {
        size_t plen = 0;
        char *prev = file_read_all(str_from_c(cur), &plen);
        if (prev) {
            while (plen > 0 && (prev[plen - 1] == '\n' || prev[plen - 1] == '\r'))
                prev[--plen] = '\0';
            if (session_load(prev, cv) == 0) {
                HANDLE f = CreateFileA(prev, FILE_APPEND_DATA, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL, NULL);
                /* CreateFileA fails with INVALID_HANDLE_VALUE, which is
                 * truthy: keeping it would pass the sl->file test below
                 * and drop every record of the run silently */
                if (f != INVALID_HANDLE_VALUE) {
                    sl->file = f;
                    sl->path = xstrdup(prev);
                }
            }
            free(prev);
        }
        if (sl->file) {
            free(dir);
            free(cur);
            return;
        }
        out_puts("no previous session; starting a new one\r\n");
    }

    SYSTEMTIME t;
    GetLocalTime(&t);
    /* just the path: session_touch() creates the file, and moves the
     * --continue pointer, on the first record actually written */
    sl->path = xasprintf("%s\\%04d%02d%02d-%02d%02d%02d-%lu.jsonl", dir,
                         t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute,
                         t.wSecond, GetCurrentProcessId());
    free(cur);
    free(dir);
}

static void session_close(struct session_log *sl)
{
    session_flush(sl);
    if (sl->file)
        CloseHandle(sl->file);
    free(sl->path);
    buf_free(&sl->w);
    memset(sl, 0, sizeof *sl);
}

/* Newest .jsonl sessions in the sessions dir, by last-write time.
 * 0-byte logs are skipped: an aborted run leaves nothing to resume.
 * Returns the count written into paths (at most cap); *total, when
 * given, receives the number of resumable sessions on disk. */
static int session_list(char paths[][MAX_PATH], int cap, int *total)
{
    struct sess_ent {
        FILETIME ft;
        char name[MAX_PATH];
    };
    DA(struct sess_ent) ents = {0};
    char dir[MAX_PATH];
    snprintf(dir, sizeof dir, "%s\\sessions\\*.jsonl", g_localapp_dir);
    WIN32_FIND_DATAA fd;
    HANDLE find = FindFirstFileA(dir, &fd);
    if (find == INVALID_HANDLE_VALUE) {
        if (total)
            *total = 0;
        return 0;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        if (!fd.nFileSizeLow && !fd.nFileSizeHigh)
            continue;
        struct sess_ent e;
        e.ft = fd.ftLastWriteTime;
        size_t nl = strlen(fd.cFileName);
        if (nl >= MAX_PATH)
            nl = MAX_PATH - 1;
        memcpy(e.name, fd.cFileName, nl);
        e.name[nl] = '\0';
        DA_PUSH(ents, e);
    } while (FindNextFileA(find, &fd));
    FindClose(find);
    int n = (int)ents.n;
    if (total)
        *total = n;
    /* insertion sort, newest first */
    for (int i = 1; i < n; i++) {
        struct sess_ent e = ents.p[i];
        int j = i - 1;
        while (j >= 0 && CompareFileTime(&ents.p[j].ft, &e.ft) < 0) {
            ents.p[j + 1] = ents.p[j];
            j--;
        }
        ents.p[j + 1] = e;
    }
    if (n > cap)
        n = cap;
    for (int i = 0; i < n; i++)
        snprintf(paths[i], MAX_PATH, "%s\\sessions\\%s", g_localapp_dir,
                 ents.p[i].name);
    DA_FREE(ents);
    return n;
}

/* One /resume picker row: the session file plus the display facts
 * scanned out of it (first user prompt as the preview, user-message
 * count as the turn count, age from the file-name timestamp). */
struct sess_row {
    char path[MAX_PATH];
    char age[16];
    char preview[224];
    int turns;
};

/* "2d" / "5h" / "3m" / "now" from a session file name's local timestamp
 * (yyyymmdd-hhmmss-pid.jsonl); "--" when the name doesn't parse. */
static int sess_digits(const char *s, int n)
{
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10 + (s[i] - '0');
    }
    return v;
}

static void sess_age_of(const char *fname, char *dst, size_t cap)
{
    FILETIME ft, now;
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    if (strlen(fname) >= 15 && fname[8] == '-') {
        y = sess_digits(fname, 4), mo = sess_digits(fname + 4, 2);
        d = sess_digits(fname + 6, 2), h = sess_digits(fname + 9, 2);
        mi = sess_digits(fname + 11, 2), s = sess_digits(fname + 13, 2);
    }
    if (y >= 1601 && mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && h >= 0
        && h <= 23 && mi >= 0 && mi <= 59 && s >= 0 && s <= 59) {
        SYSTEMTIME st = { (WORD)y, (WORD)mo, 0, (WORD)d, (WORD)h, (WORD)mi,
                          (WORD)s, 0 };
        SYSTEMTIME nowst;
        GetLocalTime(&nowst);
        if (SystemTimeToFileTime(&st, &ft)
            && SystemTimeToFileTime(&nowst, &now)) {
            ULARGE_INTEGER a, b;
            a.LowPart = ft.dwLowDateTime;
            a.HighPart = ft.dwHighDateTime;
            b.LowPart = now.dwLowDateTime;
            b.HighPart = now.dwHighDateTime;
            unsigned long long secs = a.QuadPart >= b.QuadPart
                                          ? 0
                                          : (b.QuadPart - a.QuadPart) / 10000000ULL;
            if (secs < 60)
                snprintf(dst, cap, "now");
            else if (secs < 3600)
                snprintf(dst, cap, "%llum", secs / 60);
            else if (secs < 86400)
                snprintf(dst, cap, "%lluh", secs / 3600);
            else
                snprintf(dst, cap, "%llud", secs / 86400);
            return;
        }
    }
    snprintf(dst, cap, "--");
}

/* Scan one session file for the picker row: the first user prompt's
 * first line (cut at a UTF-8 char boundary) and the user-message
 * count. Files are read up to 2MB — the preview lives at the top and
 * the count is cosmetic. */
static void sess_scan_file(struct sess_row *row)
{
    row->preview[0] = '\0';
    row->turns = 0;
    size_t len = 0;
    char *data = file_slurp(str_from_c(row->path), &len, NULL, NULL,
                            2 * 1024 * 1024, 0);
    if (!data)
        return;
    struct arena a;
    arena_init(&a, 8 * 1024);
    char *p = data;
    while (*p) {
        char *nl = strchr(p, '\n');
        size_t llen = nl ? (size_t)(nl - p) : strlen(p);
        /* gate: only user-message records matter and kk writes them with
         * this literal; the parse below still decides exactly, so content
         * that merely quotes the literal just costs one extra parse */
        if (mem_find(p, llen, "\"role\":\"user\"", 13)) {
            arena_reset(&a);
            struct jnode *v = json_parse(&a, p, llen);
            if (v && v->tag == J_OBJ) {
                struct jnode *type = jobj_get(v, "type");
                struct jnode *role = jobj_get(v, "role");
                if (type && type->tag == J_STR
                    && str_eqc(type->raw, "message") && role
                    && role->tag == J_STR && str_eqc(role->raw, "user")) {
                    row->turns++;
                    if (!row->preview[0]) {
                        struct jnode *jc = jobj_get(v, "content");
                        if (jc && jc->tag == J_STR) {
                            struct buf b = BUF_INIT;
                            jdecode_str(jc->raw, &b);
                            size_t i = 0;
                            while (i < b.len && b.p[i] != '\n'
                                   && b.p[i] != '\r')
                                i++;
                            size_t take = i < sizeof row->preview - 1
                                              ? i
                                              : sizeof row->preview - 1;
                            take = u8_floor(b.p, take);
                            memcpy(row->preview, b.p, take);
                            row->preview[take] = '\0';
                            buf_free(&b);
                        }
                    }
                }
            }
        }
        p = nl ? nl + 1 : p + llen;
    }
    arena_free(&a);
    free(data);
}

/* Switch the live conversation to another session file: closes the
 * current log, replays the file, reopens it for append and points
 * --continue at it. Returns 0 on success, -1 when the file could not
 * be loaded (a fresh session is open again in that case). Silent: the
 * caller owns the screen (clear / replay / notice). */
static int session_switch(struct session_log *slog, struct conversation *cv,
                          const char *path)
{
    session_close(slog);
    conv_truncate(cv, 0);
    if (session_load(path, cv) != 0) {
        session_open(slog, 0, cv);
        return -1;
    }
    slog->path = xstrdup(path);
    slog->file = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (slog->file == INVALID_HANDLE_VALUE)
        slog->file = NULL; /* session_touch retries the open per record */
    session_point_current(path); /* make --continue follow the resumed session */
    return 0;
}

/* ki's session transition: reset styles, wipe the screen AND the
 * scrollback (CSI 3J — 2J alone leaves the old session one scroll-away),
 * home the cursor. The stale transcript watermark resets with it. */
static void session_reset_screen(void)
{
    if (!g_emit_vt)
        return;
    out_puts("\x1b[0m\x1b[2J\x1b[3J\x1b[H");
}

/* Re-render a loaded conversation onto the cleared screen: the same
 * shapes the live turn paints — ▌ user lines, markdown assistant text,
 * ● tool calls with dimmed output. Display == model view for history
 * too: nothing the session log holds is hidden from the screen. */
static void conv_replay(struct conversation *cv)
{
    for (size_t i = 0; i < cv->msgs.n; i++) {
        struct message *m = &cv->msgs.p[i];
        if (strcmp(m->role, "user") == 0) {
            if (!m->content)
                continue;
            const char *s = m->content;
            while (*s) {
                char *nl = strchr(s, '\n');
                size_t n = nl ? (size_t)(nl - s) : strlen(s);
                user_line_show(s, n);
                s += n + (nl ? 1 : 0);
            }
        } else if (strcmp(m->role, "assistant") == 0) {
            if (m->content && *m->content) {
                struct renderer rr;
                memset(&rr, 0, sizeof rr); /* init frees first */
                renderer_init(&rr);
                renderer_set_width(&rr);
                renderer_text(&rr, m->content, strlen(m->content));
                renderer_end_turn(&rr);
                renderer_init(&rr); /* release the block buffers */
            }
            for (size_t c = 0; c < m->n_calls; c++) {
                struct arena ta;
                arena_init(&ta, 8 * 1024);
                struct jnode *aj = json_parse(&ta, m->calls[c].args,
                                              strlen(m->calls[c].args));
                if (aj && aj->tag != J_OBJ)
                    aj = NULL;
                char *summary = aj ? args_summary(aj, m->calls[c].name)
                                   : xstrdup("");
                tool_show_call(m->calls[c].name, summary);
                free(summary);
                arena_free(&ta);
            }
        } else if (strcmp(m->role, "tool") == 0 && m->content) {
            /* mirror the live display policy: quiet tools (read) put
             * file content in the model only — failures still show */
            const char *tname = NULL;
            for (size_t j = i; j-- > 0 && i - j < 8;) {
                struct message *am = &cv->msgs.p[j];
                if (strcmp(am->role, "assistant") != 0 || !am->n_calls)
                    continue;
                for (size_t c = 0; c < am->n_calls; c++)
                    if (am->calls[c].id && m->tool_call_id
                        && strcmp(am->calls[c].id, m->tool_call_id) == 0)
                        tname = am->calls[c].name;
                if (tname)
                    break;
            }
            const struct tool_spec *ts = tname ? tool_lookup(tname) : NULL;
            if (!ts || !ts->quiet_ok) {
                tool_show_exit(m->content);
                tool_show_output(m->content);
            } else if (strncmp(m->content, "error:", 6) == 0) {
                tool_show_exit(m->content);
            }
        }
    }
}

/* ==========================================================================
 * 9. ui — REPL: event-based line editor, slash commands, AGENTS.md
 * ========================================================================== */

/* --- AGENTS.md hierarchy: cwd upward, parent-first ---------------------- */

static char *load_agents_md(void)
{
    char cwd[MAX_PATH];
    if (!GetCurrentDirectoryA(MAX_PATH, cwd))
        return NULL;
    /* collect paths cwd -> root, then concatenate root-first */
    char *paths[64];
    int n = 0;
    char *cur = xstrdup(cwd);
    for (;;) {
        if (n < 64)
            paths[n++] = xasprintf("%s\\AGENTS.md", cur);
        char *slash = strrchr(cur, '\\');
        if (!slash || slash == cur)
            break;
        *slash = '\0';
    }
    free(cur);

    struct buf out = BUF_INIT;
    int any = 0;
    for (int i = n - 1; i >= 0; i--) {
        size_t len = 0;
        char *data = file_read_all(str_from_c(paths[i]), &len);
        if (data) {
            if (any)
                buf_appends(&out, "\n\n");
            buf_appends(&out, data);
            free(data);
            any = 1;
        }
        free(paths[i]);
    }
    return any ? buf_detach(&out) : NULL;
}

/* --- skills: index in the prompt, bodies pulled with read ---------------- */

#define SKILL_ROOT_MAX  2
#define SKILL_MAX       32
#define SKILL_DESC_MAX  240  /* what a skill is + when to use it fits in the
                              * leading sentences; the rest of these fields is
                              * enumerated trigger phrasings, and every byte of
                              * the index is re-sent on every round */
#define SKILL_HEAD_MAX  16384 /* only the frontmatter is ever looked at */
#define SKILL_INDEX_MAX 12288

/* Where a skill description ends once it is over the ceiling: at the last
 * sentence boundary inside it, because the routing half ("Use when ...") is
 * what must survive; failing that at a word boundary, never inside a UTF-8
 * sequence. A CJK full stop is 0xE3 0x80 0x82. */
static size_t skill_desc_cut(const char *d, size_t ceiling)
{
    size_t cut = u8_floor(d, ceiling);
    size_t sent = 0;
    for (size_t k = 1; k < cut; k++) {
        char c = d[k];
        int stop = (c == '.' || c == '!' || c == '?' || c == ';')
                   && (k + 1 >= cut || d[k + 1] == ' ' || d[k + 1] == '\n');
        if (!stop && (unsigned char)c == 0xE3 && k + 2 < cut
            && (unsigned char)d[k + 1] == 0x80
            && (unsigned char)d[k + 2] == 0x82)
            stop = 1;
        if (stop)
            sent = k + 1; /* keep the mark with the sentence */
    }
    if (sent >= cut / 2)
        return sent;
    size_t floor_at = cut > 40 ? cut - 40 : 0;
    size_t w = cut;
    while (w > floor_at && d[w] != ' ')
        w--;
    return w > floor_at ? w : cut;
}

/* Collapse a byte run into single-spaced text: YAML folds block scalars
 * across indented lines, and the index wants one line per skill. */
static void buf_append_collapsed(struct buf *b, const char *s, size_t n)
{
    int pending = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            pending = b->len != 0;
            continue;
        }
        if (pending)
            buf_appendc(b, ' ');
        pending = 0;
        buf_appendc(b, c);
    }
}

/* One top-level frontmatter key. Handles `key: value`, `key: "value"` and
 * `key: |` / `key: >` block scalars (whose text is the indented run below).
 * Returns a heap string (possibly empty) or NULL when the key is absent. */
static char *fm_value(const char *fm, const char *key)
{
    const size_t klen = strlen(key);
    const char *p = fm;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        if (strncmp(p, key, klen) == 0 && p[klen] == ':') {
            const char *v = p + klen + 1;
            while (*v == ' ' || *v == '\t')
                v++;
            const char *vend;
            int block = 0;
            if (*v == '|' || *v == '>') {
                /* a block scalar is declared by | or > with nothing but
                 * chomping/indent indicators left on the line */
                const char *t = v + 1;
                while (t < eol && (*t == '-' || *t == '+'
                                   || (*t >= '0' && *t <= '9')))
                    t++;
                while (t < eol && (*t == ' ' || *t == '\t'))
                    t++;
                block = (t == eol);
            }
            if (block) {
                /* the value is the indented run BELOW the indicator */
                v = eol ? eol + 1 : v + strlen(v);
                const char *q = v, *last = v;
                while (*q) {
                    const char *qe = strchr(q, '\n');
                    size_t ql = qe ? (size_t)(qe - q) : strlen(q);
                    if (ql == 3 && strncmp(q, "---", 3) == 0)
                        break; /* closing fence of the frontmatter */
                    int blank = 1;
                    for (size_t i = 0; i < ql; i++)
                        if (q[i] != ' ' && q[i] != '\t' && q[i] != '\r')
                            blank = 0;
                    if (!blank && q[0] != ' ' && q[0] != '\t')
                        break; /* next key at column 0 ends the block */
                    last = qe ? qe + 1 : q + ql;
                    q = last;
                }
                vend = last;
            } else {
                vend = eol ? eol : v + strlen(v);
                while (vend > v && (vend[-1] == ' ' || vend[-1] == '\t'
                                    || vend[-1] == '\r'))
                    vend--;
                if (vend - v >= 2 && (*v == '"' || *v == '\'')
                    && vend[-1] == *v) {
                    v++;
                    vend--;
                }
            }
            struct buf b = BUF_INIT;
            buf_append_collapsed(&b, v, (size_t)(vend - v));
            return buf_detach(&b);
        }
        p = eol ? eol + 1 : NULL;
    }
    return NULL;
}

/* Index entry for one skill directory, or NULL to skip it. */
static void skill_describe(const char *dir, const char *dname, struct buf *out,
                           size_t *bytes)
{
    char *path = xasprintf("%s\\SKILL.md", dir);
    size_t len = 0;
    char *data = file_read_head(str_from_c(path), SKILL_HEAD_MAX, &len);
    if (!data)
        goto done;
    char *fm = data;
    if ((unsigned char)fm[0] == 0xEF && (unsigned char)fm[1] == 0xBB
        && (unsigned char)fm[2] == 0xBF)
        fm += 3; /* UTF-8 BOM */
    if (strncmp(fm, "---", 3) != 0)
        goto done_file;
    char *end = strstr(fm + 3, "\n---");
    if (!end)
        goto done_file; /* unterminated frontmatter: not worth guessing */
    *end = '\0'; /* bound the key scan: fm_value must not read into the body */

    char *name = fm_value(fm, "name");
    char *desc = fm_value(fm, "description");
    if (!name || !*name) {
        free(name);
        name = xstrdup(dname); /* the directory is the fallback name */
    }
    size_t dlen = desc ? strlen(desc) : 0;
    int clipped = 0;
    if (dlen > SKILL_DESC_MAX) {
        dlen = skill_desc_cut(desc, SKILL_DESC_MAX);
        desc[dlen] = '\0';
        clipped = 1;
    }
    size_t need = strlen(name) + dlen + strlen(path) + 16;
    if (*bytes + need > SKILL_INDEX_MAX) {
        free(name);
        free(desc);
        goto done_file;
    }
    *bytes += need;
    buf_appends(out, "- ");
    buf_appends(out, name);
    if (dlen) {
        buf_appends(out, ": ");
        buf_append_n(out, desc, dlen);
        if (clipped)
            buf_appends(out, "\xE2\x80\xA6"); /* …: the body is one read away */
    }
    buf_appends(out, "\n  \xE2\x86\x92 read "); /* → */
    buf_appends(out, path);
    buf_appends(out, "\n");
    free(name);
    free(desc);
done_file:
    free(data);
done:
    free(path);
}

/* <root>/<name>/SKILL.md for every skill directory under each root. Project
 * skills come first so a workspace can shadow a user-level name. */
static char *load_skills(void)
{
    char *roots[SKILL_ROOT_MAX];
    int nroots = 0;
    /* project root first: a workspace shadows a user-level name */
    char cwd[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, cwd))
        roots[nroots++] = xasprintf("%s\\.agents\\skills", cwd);
    char *home = env_get("USERPROFILE");
    if (home && nroots < SKILL_ROOT_MAX)
        roots[nroots++] = xasprintf("%s\\.agents\\skills", home);
    free(home);

    DA(char *) seen = {0};
    struct buf out = BUF_INIT;
    size_t bytes = 0;
    int listed = 0;

    for (int r = 0; r < nroots && listed < SKILL_MAX; r++) {
        char *pat = xasprintf("%s\\*", roots[r]);
        WIN32_FIND_DATAA fd;
        HANDLE find = FindFirstFileA(pat, &fd);
        free(pat);
        if (find == INVALID_HANDLE_VALUE)
            continue; /* root absent: the common case */
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                continue;
            if (fd.cFileName[0] == '.')
                continue;
            int dup = 0;
            for (size_t i = 0; i < seen.n; i++)
                if (strcmp(seen.p[i], fd.cFileName) == 0)
                    dup = 1;
            if (dup)
                continue;
            char *dir = xasprintf("%s\\%s", roots[r], fd.cFileName);
            skill_describe(dir, fd.cFileName, &out, &bytes);
            DA_PUSH(seen, xstrdup(fd.cFileName));
            listed++;
            free(dir);
        } while (listed < SKILL_MAX && FindNextFileA(find, &fd));
        FindClose(find);
    }
    for (size_t i = 0; i < seen.n; i++)
        free(seen.p[i]);
    DA_FREE(seen);
    for (int r = 0; r < nroots; r++)
        free(roots[r]);
    if (!out.len) {
        buf_free(&out);
        return NULL;
    }
    struct buf head = BUF_INIT;
    buf_appends(&head,
                "# Skills\n\n"
                "Skill guides installed on this machine. A line below is a "
                "summary, not the instructions: when a task matches one, "
                "read its SKILL.md and follow it before acting, and read "
                "any file it points to the same way. Never act on a skill "
                "you have not read.\n\n");
    buf_append_n(&head, out.p, out.len);
    buf_free(&out);
    return buf_detach(&head);
}

/* --- slash command menu (ki-style picker under the composer) ----------- */

static const struct {
    const char *name, *desc;
} KK_COMMANDS[] = {
    { "/new", "开启全新会话" },
    { "/resume", "切换到其他会话" },
    { "/goal", "自主目标模式：长任务连续推进，✅ 收尾" },
    { "/skills", "列出模型可按需读取的 skill" },
    { "/compact", "把早期历史压缩为摘要" },
};
#define KK_N_COMMANDS (sizeof KK_COMMANDS / sizeof KK_COMMANDS[0])
#define EDIT_MENU_MAX 8

/* One dim horizontal rule, cached per width: the menu/picker draw the plain
 * form, the composer the dim-red one. Both run on the main thread. */
static void rule_buf(struct buf *b, int red)
{
    static struct buf rules[2];
    static int rule_cols[2];
    int k = red ? 1 : 0;
    if (rule_cols[k] != g_term_cols) {
        buf_reset(&rules[k]);
        buf_appends(&rules[k], red ? "\x1b[2m\x1b[31m" : "\x1b[2m");
        /* the editor renders only when docked, which requires VT */
        int n = red ? g_term_cols : g_term_cols - 1;
        for (int i = 0; i < n; i++)
            buf_appends(&rules[k], "─");
        buf_appends(&rules[k], "\x1b[0m");
        rule_cols[k] = g_term_cols;
    }
    buf_append_n(b, rules[k].p, rules[k].len);
}

static void ui_rule(int row)
{
    static struct buf b; /* main thread only, like out_frame_printf */
    buf_reset(&b);
    buf_appendf(&b, "\x1b[%d;1H\x1b[2K", row);
    rule_buf(&b, 0);
    out_frame_write(b.p, b.len);
}

/* ki's command panel: rule, header, up to cap entries from idx[from..],
 * rule, key hints. Returns
 * the number of entries drawn. */
static int ui_cmd_panel(int base, const int *idx, int count, int from, int sel,
                        const char *header, const char *hints, int cap)
{
    /* the caller owns the geometry: cap is already screen-clamped */
    int k = count - from;
    if (k > cap)
        k = cap;
    if (k < 0)
        k = 0;
    ui_rule(base);
    out_frame_printf("\x1b[%d;1H\x1b[2K%s", base + 1, header);
    for (int i = 0; i < k; i++) {
        const char *name = KK_COMMANDS[idx[from + i]].name;
        const char *desc = KK_COMMANDS[idx[from + i]].desc;
        if (from + i == sel)
            out_frame_printf("\x1b[%d;1H\x1b[2K\x1b[1m%s\x1b[0m %s", base + 2 + i,
                             name, desc);
        else
            out_frame_printf("\x1b[%d;1H\x1b[2K\x1b[2m%s %s\x1b[0m", base + 2 + i,
                             name, desc);
    }
    ui_rule(base + 2 + k);
    out_frame_printf("\x1b[%d;1H\x1b[2K\x1b[2m%s\x1b[0m", base + 3 + k, hints);
    return k;
}

/* --- console line editor --------------------------------------------- */

enum edit_result {
    EDIT_LINE,
    EDIT_EOF,
    EDIT_CANCEL, /* Ctrl+C pressed */
};

struct editor {
    struct buf text;
    size_t cur; /* cursor as byte index into text */
    DA(char *) history;
    int hist_pos; /* browsing position; == history.n when on the draft */
    struct buf undo_text; /* single-level draft undo (Ctrl+Z) */
    size_t undo_cur;
    int undo_valid;
    struct buf saved_draft; /* the live draft, parked while browsing history */
    size_t saved_cur;
    int saved_valid;
    int home_row;   /* screen row the draft frame starts on (1-based) */
    int drawn_rows; /* rows the last frame occupied: shrink erases them */
    int menu_base;  /* first menu row on screen (menu opens above the panel) */
    int menu_count; /* entries currently drawn */
    int menu_from;  /* sliding window start */
    int menu_open;  /* a menu is on screen: covered rows are captured */
    int menu_height;/* total captured/drawn panel height */
    int menu_sel;   /* highlighted entry */
    int menu_match[KK_N_COMMANDS];
};

static void editor_init(struct editor *e)
{
    memset(e, 0, sizeof *e);
}

static void editor_free(struct editor *e)
{
    buf_free(&e->text);
    buf_free(&e->undo_text);
    buf_free(&e->saved_draft);
    for (size_t i = 0; i < e->history.n; i++)
        free(e->history.p[i]);
    DA_FREE(e->history);
}

/* Single-level draft undo: destructive edits snapshot the draft first,
 * Ctrl+Z swaps it back (again = redo). The restore half lives next to
 * edit_repaint, which it needs. */
static void edit_undo_save(struct editor *e)
{
    buf_free(&e->undo_text);
    buf_append_n(&e->undo_text, e->text.p, e->text.len);
    e->undo_cur = e->cur;
    e->undo_valid = 1;
}

/* Advance one visual row of the draft: on entry *off is that row's first byte,
 * on return *off is the first byte of the NEXT row (an explicit '\n' is
 * consumed, an auto-wrap is not) and *row / *col are updated. One definition
 * of "visual row" for the cursor seek, the window and the row jump alike: if
 * those three ever disagreed, the caret lands on the wrong line.
 *
 * Returns 1 when a row boundary was crossed (the row that just closed is
 * *row - 1) and 0 when the draft ended INSIDE this row (*off is len, *col is
 * the column it ended at, and *row is this row's index). Callers cannot tell
 * those apart from *off alone, and guessing wrong shifts every row after it.
 *
 * Printable ASCII is bulk-skipped at one column per byte: a draft is almost
 * entirely ASCII, and the per-codepoint path paid a decode plus a width
 * lookup per character on every keystroke. */
static int edit_row_step(const char *s, size_t len, size_t cols, size_t *off,
                         int *row, size_t *col)
{
    size_t i = *off;
    while (i < len) {
        if (s[i] == '\n') {
            i++;
            (*row)++;
            *col = 0;
            *off = i;
            return 1;
        }
        if (s[i] == '\x1B') {
            i += 2; /* ESC [ */
            while (i < len && s[i] != 'm')
                i++;
            i++; /* the final 'm' */
            continue;
        }
        unsigned char b = (unsigned char)s[i];
        if (b >= 0x20 && b < 0x80) {
            size_t room = cols - *col;
            if (room == 0)
                break; /* the row is full: wrap before this byte */
            size_t run = ascii_run(s + i, room < len - i ? room : len - i);
            if (run == 0)
                break; /* a wide glyph comes next: decode it below */
            i += run;
            *col += run;
            continue;
        }
        uint32_t cp;
        size_t cl = u8_step(s + i, len - i, &cp);
        size_t cw = (size_t)u8_cp_width(cp);
        if (*col + cw > cols)
            break;
        *col += cw;
        i += cl;
    }
    if (i >= len) {
        *off = i; /* the draft ends inside this row: col stands as it is */
        return 0;
    }
    (*row)++;
    *col = 0;
    *off = i;
    return 1;
}

/* Walk s[0..len) accumulating the visual row and column: an explicit
 * '\n' resets the column and advances a row, the terminal auto-wraps
 * past the last column, SGR sequences are zero-width. */
static void edit_walk(const char *s, size_t len, size_t cols, size_t *rows,
                      size_t *col)
{
    size_t off = 0, c = 0;
    int row = 0;
    while (off < len)
        edit_row_step(s, len, cols, &off, &row, &c);
    *rows = (size_t)row;
    *col = c;
}

/* pi-style composer frame: a dim-red rule above and below the draft rows,
 * no prompt glyph. Drafts taller than the window render the rows around
 * the cursor with an ↑/↓ N more hint; when the frame does not fit above
 * the dock region's bottom the transcript scrolls up to make room. */
#define EDIT_WINDOW_ROWS 9

/* One visible draft row: a byte range into e->text.p. */
struct edit_vrow {
    size_t off;
    size_t len;
};

static void edit_rule_append(struct buf *frame)
{
    rule_buf(frame, 1);
}

/* The visible window of the draft: visual rows [lo..lo+wcap) with the * cursor row kept inside. Fills rows[] (up to wcap) and reports the
 * cursor's row/col and the draft's total visual row count. Row breaking
 * matches edit_walk exactly (\n and auto-wrap at cols), so the cursor
 * row from edit_walk indexes into the same rows. */
static int edit_window(const struct editor *e, int wcap, struct edit_vrow *rows,
                       int *lo_out, int *cur_row_out, size_t *cur_col_out,
                       int *total_out)
{
    size_t cols = (size_t)g_term_cols;
    size_t r = 0, c = 0;
    edit_walk(e->text.p, e->cur, cols, &r, &c);
    int cur_row = (int)r;
    *cur_col_out = c;

    int lo = cur_row > wcap - 1 ? cur_row - (wcap - 1) : 0;
    *lo_out = lo;

    /* one pass splits the draft into rows; each range is [start, end) minus
     * the terminating '\n' — the frame adds its own CRLF */
    size_t off = 0, w = 0;
    int row = 0, filled = 0;
    while (off < e->text.len) {
        size_t start = off;
        int closed = edit_row_step(e->text.p, e->text.len, cols, &off, &row, &w);
        size_t end = off;
        if (end > start && e->text.p[end - 1] == '\n')
            end--;
        if ((closed ? row - 1 : row) >= lo && filled < wcap)
            rows[filled++] = (struct edit_vrow){ start, end - start };
        if (!closed)
            break;
    }
    *total_out = row + 1;
    *cur_row_out = cur_row;
    return filled;
}

/* Visible-row budget for the docked composer's draft window: up to
 * EDIT_WINDOW_ROWS, shrinking only on tiny terminals so the panel fits
 * between the scroll region and the screen bottom. */
static int edit_window_cap(void)
{
    int wcap = g_term_rows - 6;
    if (wcap > EDIT_WINDOW_ROWS)
        wcap = EDIT_WINDOW_ROWS;
    if (wcap < 1)
        wcap = 1;
    return wcap;
}

/* Compose the cursor-positioning escape from a window position already
 * computed by edit_window (no extra walk on the keystroke path). */
static int edit_cursor_ctl_at(const struct editor *e, size_t cur_col,
                              int cur_row, int lo, char *ctl, size_t cap)
{
    size_t cols = (size_t)g_term_cols;
    /* bc can equal the full width on a wrapped full row, where col+1
     * would be off-screen — clamp onto the last column */
    size_t ctl_col = cur_col + 1 > cols ? cols : cur_col + 1;
    return snprintf(ctl, cap, "\x1b[%d;%zuH",
                    e->home_row + 1 + cur_row - lo, ctl_col);
}

/* Seek the console cursor without rewriting the line: pure cursor moves
 * leave the text pixels intact, so O(line) console traffic per keypress
 * buys nothing. */
static void edit_cursor_pos(struct editor *e)
{
    size_t cols = (size_t)g_term_cols;
    size_t br = 0, bc = 0;
    edit_walk(e->text.p, e->cur, cols, &br, &bc);
    /* the frame stacks a rule above the window, so the cursor's screen
     * row is home_row + 1 + (its draft row - window start) */
    int wcap = edit_window_cap();
    int lo = br > (size_t)(wcap - 1) ? (int)br - (wcap - 1) : 0;
    char ctl[48];
    int cn = edit_cursor_ctl_at(e, bc, (int)br, lo, ctl, sizeof ctl);
    out_frame_write(ctl, (size_t)cn);
}

static void edit_render(struct editor *e)
{
    /* one composed frame, one console write per keystroke */
    static struct buf frame; /* editor runs on the main thread only */
    buf_reset(&frame);
    int old_home = e->home_row, old_drawn = e->drawn_rows;

    struct edit_vrow rows[EDIT_WINDOW_ROWS];
    int lo = 0, total = 0, cur_row = 0;
    size_t cur_col = 0;
    int wcap = edit_window_cap();
    int shown = edit_window(e, wcap, rows, &lo, &cur_row, &cur_col, &total);
    int above = lo, below = total - lo - shown;
    int hint = above > 0 || below > 0;
    int need = 2 + shown + hint + 1; /* rules + rows + hint + status row */
    /* bottom dock: the panel's last row pins to the screen bottom, so
     * the top edge rises as the draft grows — output scrolls above the
     * panel in the scroll region and never displaces it */
    e->home_row = g_term_rows - need + 1;
    if (e->home_row < 1)
        e->home_row = 1;

    /* the scroll region tracks the panel's actual height: its bottom is
     * the row just above the panel's top rule, so transcript output
     * bottom-aligns against the panel with no reserved dead rows. When
     * the panel grows, shift the transcript up first (SU under the old
     * region) so the draft never covers it. */
    int rb = e->home_row - 1;
    int rise = old_drawn > 0 ? old_home - e->home_row : 0;
    if (rise > 0) {
        AcquireSRWLockExclusive(&g_out_lock);
        g_content_y = (SHORT)(g_content_y - rise);
        char su[24];
        int sn = snprintf(su, sizeof su, "\x1b[%dS", rise);
        out_write_unlocked(su, (size_t)sn);
        ReleaseSRWLockExclusive(&g_out_lock);
    }
    if (rb != g_region_bottom && rb >= 1) {
        g_region_bottom = rb;
        buf_appendf(&frame, "\x1b[1;%dr", rb);
    }

    /* the frame always paints from its top rule: whatever the console
     * cursor is doing, the draft lands where the dock put it */
    buf_appendf(&frame, "\x1b[%d;1H", e->home_row);
    edit_rule_append(&frame);
    int busy = (int)g_busy;
    for (int i = 0; i < shown; i++) {
        buf_appends(&frame, "\r\n");
        if (busy && cur_row - lo == i) {
            /* streaming hides the real cursor (agent writes park it at
             * the content end): paint a block caret at the draft cursor
             * so mid-turn typing still shows the insertion point */
            const char *rs = e->text.p + rows[i].off;
            size_t rlen = rows[i].len;
            size_t at = 0, w = 0;
            while (at < rlen && w < cur_col) {
                uint32_t cp;
                size_t cl = u8_step(rs + at, rlen - at, &cp);
                w += u8_cp_width(cp);
                at += cl;
            }
            if (at < rlen) {
                size_t cl = u8_len(rs + at, rlen - at);
                buf_append_n(&frame, rs, at);
                buf_appends(&frame, "\x1b[7m");
                buf_append_n(&frame, rs + at, cl);
                buf_appends(&frame, "\x1b[27m");
                buf_append_n(&frame, rs + at + cl, rlen - at - cl);
            } else if (rlen > 0 && w >= (size_t)g_term_cols) {
                /* full row: cover the last glyph instead of adding a
                 * space that would wrap to the next line */
                size_t last = rlen;
                while (last > 0 && (rs[last - 1] & 0xC0) == 0x80)
                    last--;
                if (last > 0)
                    last--;
                buf_append_n(&frame, rs, last);
                buf_appends(&frame, "\x1b[7m");
                buf_append_n(&frame, rs + last, rlen - last);
                buf_appends(&frame, "\x1b[27m");
            } else {
                buf_append_n(&frame, rs, rlen);
                buf_appends(&frame, "\x1b[7m \x1b[27m");
            }
        } else {
            buf_append_n(&frame, e->text.p + rows[i].off, rows[i].len);
        }
        buf_appends(&frame, "\x1b[0K");
    }
    if (hint) {
        buf_appends(&frame, "\r\n");
        buf_appends(&frame, "\x1b[2m\x1b[31m");
        if (above > 0)
            buf_appendf(&frame, "↑%d ", above);
        if (below > 0)
            buf_appendf(&frame, "↓%d ", below);
        buf_appends(&frame, "more\x1b[0m");
        buf_appends(&frame, "\x1b[0K");
    }
    buf_appends(&frame, "\r\n");
    edit_rule_append(&frame);
    /* the pinned status row: same builder the spinner paints with, so a
     * keystroke repaint never flickers it back to the model name */
    {
        char line[512], tail[96];
        status_line_build(line, sizeof line, tail, sizeof tail);
        buf_appends(&frame, "\r\n");
        buf_appends(&frame, line);
        buf_appends(&frame, tail);
        buf_appends(&frame, "\x1b[0K");
    }

    /* the panel is bottom-pinned: growth and shrink move the top edge,
     * so erase rows the previous frame spanned above the new top */
    if (!e->menu_open && old_drawn > 0) {
        for (int r = old_home; r < e->home_row; r++)
            buf_appendf(&frame, "\x1b[%d;1H\x1b[2K", r);
    }
    e->drawn_rows = need;
    char ctl[48];
    int cn = edit_cursor_ctl_at(e, cur_col, cur_row, lo, ctl, sizeof ctl);
    buf_append_n(&frame, ctl, (size_t)cn);
    out_frame_write(frame.p, frame.len);
}

static void edit_insert(struct editor *e, const char *s, size_t n)
{
    buf_reserve(&e->text, n);
    memmove(e->text.p + e->cur + n, e->text.p + e->cur, e->text.len - e->cur);
    memcpy(e->text.p + e->cur, s, n);
    e->text.len += n;
    e->cur += n;
}

static void edit_delete_before(struct editor *e)
{
    if (e->cur == 0)
        return;
    size_t prev = u8_prev(e->text.p, e->cur);
    memmove(e->text.p + prev, e->text.p + e->cur, e->text.len - e->cur);
    e->text.len -= e->cur - prev;
    e->cur = prev;
}

static void edit_delete_at(struct editor *e)
{
    if (e->cur >= e->text.len)
        return;
    size_t next = u8_next(e->text.p, e->text.len, e->cur);
    memmove(e->text.p + e->cur, e->text.p + next, e->text.len - next);
    e->text.len -= next - e->cur;
}

static void edit_kill_word(struct editor *e)
{
    size_t i = e->cur;
    while (i > 0 && e->text.p[i - 1] == ' ')
        i--;
    while (i > 0 && e->text.p[i - 1] != ' ')
        i--;
    if (i == e->cur)
        return;
    memmove(e->text.p + i, e->text.p + e->cur, e->text.len - e->cur);
    e->text.len -= e->cur - i;
    e->cur = i;
}

static void edit_history_move(struct editor *e, int dir)
{
    if (e->history.n == 0)
        return;
    long pos = (long)e->hist_pos + dir;
    if (pos < 0)
        pos = 0;
    if (pos > (long)e->history.n)
        pos = (long)e->history.n;
    if (pos == (long)e->hist_pos)
        return; /* already there: keep the draft */
    if ((long)e->hist_pos == (long)e->history.n) {
        /* leaving the live draft: park it so coming back down restores
         * it whole (a multi-line paste must not vanish into an empty
         * draft row) */
        buf_free(&e->saved_draft);
        buf_append_n(&e->saved_draft, e->text.p, e->text.len);
        e->saved_cur = e->cur;
        e->saved_valid = 1;
    }
    e->text.len = 0;
    e->cur = 0;
    e->hist_pos = (int)pos;
    if (pos == (long)e->history.n) {
        if (e->saved_valid) {
            buf_append_n(&e->text, e->saved_draft.p, e->saved_draft.len);
            e->cur = e->saved_cur;
        }
        return;
    }
    edit_insert(e, e->history.p[pos], strlen(e->history.p[pos]));
}

/* Visual row count of the draft (auto-wrap counts, like edit_walk). */
static int edit_visrows(const struct editor *e)
{
    size_t r = 0, c = 0;
    edit_walk(e->text.p, e->text.len, (size_t)g_term_cols, &r, &c);
    return (int)r + 1;
}

/* Byte offset of visual row `trow` at column `tcol` (clamped to the
 * row's width and to the terminal width; row breaking matches
 * edit_walk). Returns e->cur when the row does not exist. */
static size_t edit_row_at(const struct editor *e, int trow, size_t tcol)
{
    size_t cols = (size_t)g_term_cols;
    size_t off = 0, w = 0;
    int row = 0;
    while (row < trow) {
        if (off >= e->text.len)
            return e->cur; /* past the last row: no move */
        edit_row_step(e->text.p, e->text.len, cols, &off, &row, &w);
    }
    /* off is the target row's first byte: walk it to the kept column */
    while (off < e->text.len && e->text.p[off] != '\n' && w < tcol) {
        if (e->text.p[off] == '\x1B') {
            off += 2;
            while (off < e->text.len && e->text.p[off] != 'm')
                off++;
            off++;
            continue;
        }
        uint32_t cp;
        size_t cl = u8_step(e->text.p + off, e->text.len - off, &cp);
        size_t cw = (size_t)u8_cp_width(cp);
        if (w + cw > cols)
            break;
        w += cw;
        off += cl;
    }
    return off;
}

/* Up/down inside a multi-row draft: move the cursor one visual row,
 * keeping its column (clamped to the target row's width). Returns 0
 * when the cursor is already on the boundary row, so the caller can
 * fall through to history. */
static int edit_row_move(struct editor *e, int dir)
{
    size_t r = 0, c = 0;
    edit_walk(e->text.p, e->cur, (size_t)g_term_cols, &r, &c);
    int target = (int)r + dir;
    if (target < 0)
        return 0;
    size_t at = edit_row_at(e, target, c);
    if (at == e->cur)
        return 0;
    e->cur = at;
    return 1;
}

/* --- command panel overlay --------------------------------------------- */

/* The panel draws over the rows below the composer (the blank spacer, the
 * status line and whatever empty rows remain). Opening captures those rows
 * — characters and attributes — so closing puts the screen back exactly. */
static CHAR_INFO *menu_cap;
static SHORT menu_cap_cols;
static int menu_cap_base, menu_cap_rows;

static void menu_capture(int base, int rows)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    int cols = 80;
    if (g_console_out && GetConsoleScreenBufferInfo(g_hstdout, &csbi))
        cols = csbi.dwSize.X;
    if (cols > 500)
        cols = 500;
    menu_cap = xrealloc(menu_cap, (size_t)rows * (size_t)cols * sizeof *menu_cap);
    menu_cap_cols = (SHORT)cols;
    menu_cap_base = base;
    menu_cap_rows = rows;
    COORD size = { (SHORT)cols, (SHORT)rows };
    COORD org = { 0, 0 };
    /* console buffer coords are 0-based; base is a 1-based screen row */
    SMALL_RECT rd = { 0, (SHORT)(base - 1), (SHORT)(cols - 1),
                      (SHORT)(base + rows - 2) };
    ReadConsoleOutputW(g_hstdout, menu_cap, size, org, &rd);
}

static void menu_restore(void)
{
    if (!menu_cap_rows)
        return;
    COORD size = { menu_cap_cols, (SHORT)menu_cap_rows };
    COORD org = { 0, 0 };
    SMALL_RECT dst = { 0, (SHORT)(menu_cap_base - 1), (SHORT)(menu_cap_cols - 1),
                       (SHORT)(menu_cap_base + menu_cap_rows - 2) };
    WriteConsoleOutputW(g_hstdout, menu_cap, size, org, &dst);
    menu_cap_rows = 0;
}

/* Clipboard TEXT (CF_UNICODETEXT) as UTF-8, or NULL. */
static char *clipboard_text_get(void)
{
    char *out = NULL;
    if (OpenClipboard(NULL)) {
        HANDLE h = GetClipboardData(CF_UNICODETEXT);
        if (h) {
            wchar_t *w = (wchar_t *)GlobalLock(h);
            if (w) {
                out = utf8_from_w(w);
                GlobalUnlock(h);
            }
        }
        CloseClipboard();
    }
    return out;
}

/* Ctrl+V, one handler for everything on the clipboard: text pastes
 * into the draft whole (newlines included, never a submit), an
 * image-only clipboard attaches as a PNG path. Terminals that swallow
 * Ctrl+V (Windows Terminal pastes text itself) reach here through
 * Alt+V instead. */
static void edit_paste_clipboard(struct editor *e)
{
    edit_undo_save(e); /* one Ctrl+Z takes the whole paste back */
    e->hist_pos = (int)e->history.n; /* pasting makes it the live draft */
    char *text = clipboard_text_get();
    if (text && *text) {
        struct buf norm = BUF_INIT;
        for (size_t i = 0; text[i]; i++) {
            if (text[i] == '\r') {
                if (text[i + 1] == '\n')
                    continue; /* CRLF collapses to the draft's bare LF */
                buf_appendc(&norm, '\n');
                continue;
            }
            buf_appendc(&norm, text[i]);
        }
        free(text);
        if (norm.len) {
            edit_insert(e, norm.p, norm.len);
            buf_free(&norm);
            return;
        }
        buf_free(&norm);
    } else {
        free(text);
    }
    char clip_path[MAX_PATH];
    if (clipboard_image_png(clip_path, MAX_PATH) == 0)
        edit_insert(e, clip_path, strlen(clip_path));
    else
        Beep(660, 150); /* nothing usable on the clipboard */
}

/* The draft shows the '/'-command menu: it starts with '/', is one
 * token (no space, no newline) and short. Shared by the draw path and
 * the keystroke fast path, which must open the menu the moment '/'
 * lands instead of waiting for a full repaint. */
static int edit_menu_candidate(const struct editor *e)
{
    return e->text.len >= 1 && e->text.p[0] == '/'
        && memchr(e->text.p, ' ', e->text.len) == NULL
        && memchr(e->text.p, '\n', e->text.len) == NULL
        && e->text.len < 32;
}

/* Draw / clear the command panel overlay. The panel opens above the
 * docked composer (its bottom edge sits on the panel's top rule) and is
 * height-clamped to the rows above so '/' always works. Ends with the
 * cursor back on the draft. */
static void edit_menu_draw(struct editor *e)
{
    if ((int)g_busy != 0) {
        /* the menu captures transcript rows a live turn scrolls under
         * it — restore would paste stale pixels over new content */
        e->menu_count = 0;
        return;
    }
    int match[KK_N_COMMANDS];
    int count = 0;
    if (edit_menu_candidate(e)) {
        for (size_t k = 0; k < KK_N_COMMANDS; k++) {
            const char *name = KK_COMMANDS[k].name;
            if (e->text.len <= strlen(name)
                && memcmp(name, e->text.p, e->text.len) == 0)
                match[count++] = (int)k;
        }
    }
    if (!count) {
        if (e->menu_open) {
            menu_restore();
            e->menu_open = 0;
            /* the restore leaves the cursor wherever WriteConsoleOutputW
             * lands it: only then does the draft need re-seeking */
            edit_cursor_pos(e);
        }
        e->menu_count = 0;
        return;
    }
    if (!e->menu_open) {
        /* open: fix the geometry and capture the covered rows once */
        int height = 4 + (count < EDIT_MENU_MAX ? count : EDIT_MENU_MAX);
        int avail = e->home_row - 1; /* rows above the composer panel */
        if (height > avail)
            height = avail;
        if (height < 1)
            return;
        e->menu_base = e->home_row - height;
        menu_capture(e->menu_base, height);
        e->menu_height = height;
        e->menu_open = 1;
    }
    int chrome = e->menu_height >= 5;
    int k = chrome ? e->menu_height - 4 : e->menu_height;
    if (e->menu_sel >= count)
        e->menu_sel = 0;
    if (e->menu_from > count - k)
        e->menu_from = count - k;
    if (e->menu_from < 0)
        e->menu_from = 0;
    if (e->menu_sel < e->menu_from)
        e->menu_from = e->menu_sel;
    if (e->menu_sel >= e->menu_from + k)
        e->menu_from = e->menu_sel - k + 1;
    int total = k;
    if (chrome) {
        /* stack buffer: this draws per keystroke while the menu is open */
        char hdr[160];
        char hints[80];
        int hn = snprintf(hdr, sizeof hdr,
                          "\x1b[1mResults %d\x1b[0m \x1b[2m· type to filter\x1b[0m",
                          count);
        if (hn > 0 && hn < (int)sizeof hdr)
            snprintf(hdr + hn, sizeof hdr - (size_t)hn, "\x1b[%dG\x1b[2m%d–%d\x1b[0m",
                     g_term_cols - 5,
                     e->menu_from + 1,
                     e->menu_from + (count - e->menu_from < k
                                         ? count - e->menu_from
                                         : k));
        snprintf(hints, sizeof hints,
                 "\x1b[2m↑↓ navigate   enter use   esc close\x1b[0m");
        total = ui_cmd_panel(e->menu_base, match, count, e->menu_from,
                             e->menu_sel, hdr, hints, k) + 4;
    } else {
        /* near the screen bottom: chromeless entry list so '/' always works */
        for (int i = 0; i < k; i++) {
            const char *name = KK_COMMANDS[match[e->menu_from + i]].name;
            const char *desc = KK_COMMANDS[match[e->menu_from + i]].desc;
            if (e->menu_from + i == e->menu_sel)
                out_frame_printf("\x1b[%d;1H\x1b[2K\x1b[1m%s\x1b[0m %s",
                                 e->menu_base + i, name, desc);
            else
                out_frame_printf("\x1b[%d;1H\x1b[2K\x1b[2m%s %s\x1b[0m",
                                 e->menu_base + i, name, desc);
        }
    }
    /* erase the tail of a shrunken draw (close restores the capture) */
    for (int i = total; i < e->menu_height; i++)
        out_frame_printf("\x1b[%d;1H\x1b[2K", e->menu_base + i);
    e->menu_count = count;
    if (count)
        memcpy(e->menu_match, match, (size_t)count * sizeof match[0]);
    edit_cursor_pos(e); /* back onto the draft */
}

static void edit_menu_clear(struct editor *e)
{
    if (!e->menu_base || !e->menu_open)
        return;
    menu_restore(); /* put the covered rows back exactly */
    e->menu_count = 0;
    e->menu_open = 0;
    /* the restore leaves the cursor wherever WriteConsoleOutputW lands it;
     * put it back on the draft */
    edit_cursor_pos(e);
}

/* Full repaint: the draft frame first (its shrink-erase frees rows),
 * then the command menu draws over the freed space. */
static void edit_repaint(struct editor *e)
{
    edit_render(e);
    edit_menu_draw(e);
}

/* Ctrl+Z: swap the draft back to the last snapshot (press again to
 * redo — the current draft becomes the snapshot in turn). */
static void editor_undo(struct editor *e)
{
    if (!e->undo_valid)
        return; /* nothing to undo yet */
    struct buf t = BUF_INIT;
    buf_append_n(&t, e->undo_text.p, e->undo_text.len);
    buf_reset(&e->undo_text);
    buf_append_n(&e->undo_text, e->text.p, e->text.len);
    size_t uc = e->cur;
    e->cur = e->undo_cur;
    e->undo_cur = uc;
    buf_free(&e->text);
    e->text = t;
    edit_repaint(e);
}

/* Replace the draft with the highlighted command (ki's picker contract). */
static void menu_complete(struct editor *e)
{
    const char *name = KK_COMMANDS[e->menu_match[e->menu_sel]].name;
    e->text.len = 0;
    e->cur = 0;
    edit_insert(e, name, strlen(name));
}

/* Insert bytes and repaint the full frame. There is deliberately NO in-place
 * fast path: when a wrapped row fills to the terminal edge, the computed
 * cursor column and the terminal's pending-wrap state disagree by one, and
 * in-place writes then overwrite the last visible character. One composed
 * frame per keystroke is cheap and always consistent. */
static void edit_put_bytes(struct editor *e, const char *s, size_t n)
{
    e->hist_pos = (int)e->history.n; /* typing makes it the live draft */
    edit_insert(e, s, n);
    edit_repaint(e);
}

/* Bracketed-paste collector: everything until ESC[201~ is content — CRLF
 * folds to the draft's bare LF, NULs become spaces, a 1MB cap bounds runaway
 * pastes (bytes past it are still consumed so nothing leaks into the key
 * loop), a 5s idle gap ends a truncated paste. An EMPTY body means an
 * image-only clipboard: fall back to the clipboard reader. */
static void edit_collect_paste(struct editor *e)
{
    static const char END_MARK[] = "\x1b[201~";
    const size_t MARK_LEN = sizeof END_MARK - 1; /* six bytes: ESC [ 2 0 1 ~ */
    const size_t CAP = 1u << 20;
    unsigned char pend[6];
    size_t pend_len = 0, emitted = 0;
    struct buf body = BUF_INIT;
    int swallow_lf = 0;
    for (;;) {
        unsigned char b;
        if (term_read_byte_timeout(&b, 5000) <= 0)
            break; /* truncated paste: keep what arrived */
        if (b == '\n' && swallow_lf) {
            swallow_lf = 0;
            continue;
        }
        if (b == '\r') {
            b = '\n';
            swallow_lf = 1;
        } else {
            swallow_lf = 0;
        }
        if (b == 0)
            b = ' ';
        pend[pend_len++] = b;
        while (pend_len > 0) {
            size_t prefix = pend_len < MARK_LEN ? pend_len : MARK_LEN;
            if (memcmp(pend, END_MARK, prefix) == 0) {
                if (pend_len == MARK_LEN)
                    goto done; /* complete end marker */
                break; /* a prefix of it: keep collecting */
            }
            if (emitted < CAP) {
                buf_appendc(&body, (char)pend[0]);
                emitted++;
            }
            memmove(pend, pend + 1, pend_len - 1);
            pend_len--;
        }
    }
done:
    if (body.len == 0) {
        buf_free(&body);
        edit_paste_clipboard(e);
        edit_repaint(e);
        return;
    }
    edit_undo_save(e);
    e->hist_pos = (int)e->history.n; /* pasting makes it the live draft */
    edit_insert(e, body.p, body.len);
    buf_free(&body);
    edit_repaint(e);
}

/* The composer's key loop: one raw VT byte stream decoded by hand. ReadFile +
 * ENABLE_VIRTUAL_TERMINAL_INPUT brings every sequence the terminal sends —
 * bracketed-paste markers, arrows, meta chords — intact, which the
 * INPUT_RECORD API never did (conhost's key translator ate the paste markers,
 * so multi-line paste submitted line by line). */
/* Cooked line input: no VT styling or stdin is not a console — keeps
 * scripting and pipes working. */
static enum edit_result edit_read_cooked(char **out)
{
    wchar_t wtmp[4096];
    DWORD got = 0;
    /* 4095: wtmp[got] = 0 below needs one slot at full read */
    if (!ReadConsoleW(g_hstdin, wtmp, 4095, &got, NULL) || got == 0)
        return EDIT_EOF;
    while (got > 0 && (wtmp[got - 1] == L'\n' || wtmp[got - 1] == L'\r'))
        got--;
    wtmp[got] = 0;
    *out = utf8_from_w(wtmp);
    return *out ? EDIT_LINE : EDIT_EOF;
}

static enum edit_result edit_line(struct editor *e, char **out)
{
    if (!g_emit_vt)
        return edit_read_cooked(out); /* console without VT styling */

    DWORD saved;
    if (!term_raw_begin(&saved))
        return edit_read_cooked(out);

    e->text.len = 0;
    e->cur = 0;
    e->hist_pos = (int)e->history.n;
    e->menu_count = 0;
    e->menu_from = 0;
    e->menu_sel = 0;
    e->menu_height = 0;
    e->menu_open = 0;
    e->menu_base = 0;
    e->drawn_rows = 0;
    edit_repaint(e);
    /* bracketed paste: the terminal wraps pasted text in ESC[200~ ..
     * ESC[201~ so its newlines land in the draft instead of submitting */
    /* mode switches, not content: never seek (a seek would yank the
     * caret out of the draft right after the first repaint) */
    out_frame_puts("\x1b[?2004h");

    enum edit_result result = EDIT_EOF;
    int leave = 0;
    struct buf submitted = BUF_INIT; /* the draft, stolen at submit */
    int last_cols = g_term_cols, last_rows = g_term_rows;
    int last_busy = (int)g_busy;
    while (!leave) {
        unsigned char b;
        if (!term_wait_readable(200)) {
            /* idle: pick up terminal resizes between keystrokes, and
             * re-dock the caret when a turn ends (the agent's writes
             * park the buffer cursor at the content end) */
            term_size_refresh();
            int busy = (int)g_busy;
            if (g_term_cols != last_cols || g_term_rows != last_rows
                || busy != last_busy) {
                last_cols = g_term_cols;
                last_rows = g_term_rows;
                if (last_busy && !busy)
                    out_frame_puts("\x1b[?25h"); /* the caret comes home */
                last_busy = busy;
                /* the old frame's rows are stale after a reflow: erase
                 * them before the repaint re-docks the panel (the region
                 * itself is re-emitted inside edit_render) */
                if (e->drawn_rows > 0) {
                    int last = e->home_row + e->drawn_rows;
                    for (int r = e->home_row;
                         r < last && r <= g_term_rows; r++)
                        out_frame_printf("\x1b[%d;1H\x1b[2K", r);
                }
                e->drawn_rows = 0;
                edit_repaint(e);
            }
            continue;
        }
        int rr = term_read_byte(&b);
        if (rr < 0)
            break; /* input closed */
        if (rr == 0) {
            /* conhost ate the Ctrl+Z key and surfaced its EOF mark:
             * that IS the undo request */
            editor_undo(e);
            continue;
        }

        if (b == 0x1B) {
            unsigned char s;
            if (term_read_byte_timeout(&s, 50) <= 0) {
                /* lone Esc: back to plain conversation */
                if (e->menu_open) {
                    e->text.len = 0;
                    e->cur = 0;
                    edit_repaint(e);
                }
                continue;
            }
            if (s == '[' || s == 'O') {
                /* CSI / SS3: parameter bytes, then one final byte */
                char params[16];
                size_t np;
                unsigned char final = csi_read(params, sizeof params, &np);
                if (!final)
                    continue;
                if (final == '~' && np == 3 && params[0] == '2'
                    && params[1] == '0') {
                    /* 200~ starts the collector (it runs to the end
                     * marker); a stray 201~ is ignored */
                    if (params[2] == '0')
                        edit_collect_paste(e);
                    continue;
                }
                int moved = 0;
                switch (final) {
                case 'A':
                    if (e->menu_count)
                        e->menu_sel = e->menu_sel > 0
                                          ? e->menu_sel - 1
                                          : e->menu_count - 1; /* wraps */
                    else if (edit_visrows(e) > 1) {
                        /* multi-row draft: arrows move within it, and
                         * the top edge falls through to history; the
                         * window follows the cursor, so repaint */
                        if (edit_row_move(e, -1))
                            edit_repaint(e);
                        else {
                            edit_history_move(e, -1);
                            edit_repaint(e);
                        }
                    } else
                        edit_history_move(e, -1);
                    break;
                case 'B':
                    if (e->menu_count)
                        e->menu_sel = e->menu_sel + 1 < e->menu_count
                                          ? e->menu_sel + 1
                                          : 0; /* wraps */
                    else if (edit_visrows(e) > 1) {
                        if (edit_row_move(e, +1))
                            edit_repaint(e);
                        else {
                            edit_history_move(e, +1);
                            edit_repaint(e);
                        }
                    } else
                        edit_history_move(e, +1);
                    break;
                case 'C':
                    if (e->cur < e->text.len)
                        e->cur = u8_next(e->text.p, e->text.len, e->cur);
                    moved = 1;
                    break;
                case 'D':
                    e->cur = u8_prev(e->text.p, e->cur);
                    moved = 1;
                    break;
                case 'H':
                    e->cur = 0;
                    moved = 1;
                    break;
                case 'F':
                    e->cur = e->text.len;
                    moved = 1;
                    break;
                case '~':
                    /* ESC [ 3 ~ (Delete) is the only member of the ~ family
                     * left: conhost and Windows Terminal both send Home/End as
                     * ESC [ H / ESC [ F (handled above), and Ctrl+A/Ctrl+E
                     * already cover the line ends for every other terminal. */
                    if (np == 1 && params[0] == '3') {
                        edit_undo_save(e);
                        edit_delete_at(e);
                    }
                    break;
                default:
                    break; /* unknown sequence: consumed, ignored */
                }
                if (moved && !e->menu_open) {
                    if ((int)g_busy != 0)
                        edit_repaint(e); /* the block caret needs a frame */
                    else
                        edit_cursor_pos(e);
                } else
                    edit_repaint(e);
                continue;
            }
            /* meta Alt+char: Alt+V pastes the clipboard (image or text),
             * anything else falls through literally (readline's meta) */
            if (s == 'v' || s == 'V') {
                edit_paste_clipboard(e);
                edit_repaint(e);
            } else if (s >= 0x20) {
                char tmp = (char)s;
                edit_put_bytes(e, &tmp, 1);
            }
            continue;
        }

        switch (b) {
        case '\r':
        case '\n': /* Enter: run the highlighted command, or submit */
            if (e->menu_count) {
                menu_complete(e);
                edit_render(e); /* echo the completed line */
            }
            edit_menu_clear(e);
            {
                /* the draft moves to the transcript; the docked panel
                 * stays up, empty. turn_feed_queue echoes it as the cyan
                 * bars once the turn picks it up (idle start or steer). */
                struct buf steal = e->text;
                e->text = (struct buf)BUF_INIT;
                e->cur = 0;
                submitted = steal;
            }
            edit_render(e);
            result = EDIT_LINE;
            leave = 1;
            break;
        case '\t': /* Tab: complete the highlighted command */
            if (e->menu_count) {
                menu_complete(e);
                edit_insert(e, " ", 1);
            }
            edit_repaint(e);
            break;
        case 0x03: /* Ctrl+C: empty draft cancels the running turn (idle:
                      cancel line, empty = quit) */
            if ((int)g_busy != 0 && e->text.len == 0) {
                InterlockedExchange(&g_cancel, 1);
                break;
            }
            edit_menu_clear(e);
            if (e->text.len) {
                e->text.len = 0;
                e->cur = 0;
                result = EDIT_CANCEL;
            } else {
                result = EDIT_EOF;
            }
            leave = 1;
            break;
        case 0x04: /* Ctrl+D: quit */
            edit_menu_clear(e);
            result = EDIT_EOF;
            leave = 1;
            break;
        case 0x08:
        case 0x7F:
            edit_undo_save(e);
            edit_delete_before(e);
            edit_repaint(e);
            break;
        case 0x16: /* Ctrl+V: paste whatever the clipboard holds —
                   * text into the draft, an image as a path */
            edit_paste_clipboard(e);
            edit_repaint(e);
            break;
        case 0x1A: /* Ctrl+Z: undo the last destructive edit */
            editor_undo(e);
            break;
        case 0x01: /* Ctrl+A: line start */
            e->cur = 0;
            if ((int)g_busy != 0)
                edit_repaint(e); /* the block caret needs a frame */
            else
                edit_cursor_pos(e);
            break;
        case 0x05: /* Ctrl+E: line end */
            e->cur = e->text.len;
            if ((int)g_busy != 0)
                edit_repaint(e);
            else
                edit_cursor_pos(e);
            break;
        case 0x15: /* Ctrl+U: kill line */
            edit_undo_save(e);
            e->text.len = 0;
            e->cur = 0;
            edit_repaint(e);
            break;
        case 0x10: /* Ctrl+P: history back — always available, even in a
                     multi-row draft where the arrows move the cursor */
            edit_history_move(e, -1);
            edit_repaint(e);
            break;
        case 0x0E: /* Ctrl+N: history forward */
            edit_history_move(e, +1);
            edit_repaint(e);
            break;
        case 0x17: /* Ctrl+W: kill word */
            edit_undo_save(e);
            edit_kill_word(e);
            edit_repaint(e);
            break;
        default:
            if (b < 0x20)
                break;
            {
                char seq[4];
                seq[0] = (char)b;
                size_t n = 1;
                int cont = (b & 0xE0) == 0xC0   ? 1
                    : (b & 0xF0) == 0xE0        ? 2
                    : (b & 0xF8) == 0xF0        ? 3
                                                : 0;
                for (int k = 0; k < cont; k++) {
                    unsigned char c;
                    if (term_read_byte_timeout(&c, 50) <= 0)
                        break; /* truncated UTF-8: keep the lead part */
                    seq[n++] = (char)c;
                }
                edit_put_bytes(e, seq, n);
            }
            break;
        }
    }

    edit_menu_clear(e);
    out_frame_puts("\x1b[?2004l"); /* bracketed paste off */
    if (result == EDIT_CANCEL)
        out_puts("^C\r\n");
    else if (result == EDIT_EOF)
        out_puts("\r\n");
    term_raw_end(saved);
    if (result == EDIT_LINE) {
        buf_reserve(&submitted, 1);
        submitted.p[submitted.len] = '\0';
        *out = buf_detach(&submitted);
    } else {
        buf_free(&submitted);
    }
    return result;
}

/* --- /resume full-screen session picker --------------------------------- */

/* One picker frame: header, rule, the sliding window of rows, rule,
 * key hints — drawn row-wise over the alt screen (cleared once on
 * entry, not per frame). */
static void sess_pick_draw(struct sess_row *rows, int n, int all, int from,
                           int sel, int list_rows)
{
    /* one composed frame, one console write: this redraws on every arrow key,
     * and as separate out_printf calls it cost a lock plus a vsnprintf plus a
     * WriteConsole per row */
    static struct buf frame;
    buf_reset(&frame);
    buf_appendf(&frame, "\x1b[1;1H\x1b[2K\x1b[1mSessions\x1b[0m \x1b[2m%d", n);
    if (all > n)
        buf_appendf(&frame, "/%d", all); /* older ones exist but are not listed */
    buf_appends(&frame, "\x1b[0m");
    buf_appendf(&frame, "\x1b[2;1H\x1b[2K");
    rule_buf(&frame, 0);
    for (int i = 0; i < list_rows; i++) {
        int r = from + i;
        buf_appendf(&frame, "\x1b[%d;1H\x1b[2K", 3 + i);
        if (r >= n)
            continue;
        char meta[32];
        snprintf(meta, sizeof meta, "%s · %d turn%s", rows[r].age,
                 rows[r].turns, rows[r].turns == 1 ? "" : "s");
        int mw = (int)visible_width(meta, strlen(meta));
        int avail = g_term_cols - 6 - mw - 2;
        if (avail < 12)
            avail = 12;
        char prev[128];
        trunc_cols(prev, sizeof prev, rows[r].preview, avail);
        buf_appendf(&frame, r == sel ? "\x1b[1m> %2d %s" : "\x1b[2m  %2d %s",
                    r + 1, prev);
        if (g_term_cols - mw >= 1)
            buf_appendf(&frame, "\x1b[%dG%s", g_term_cols - mw, meta);
        buf_appends(&frame, "\x1b[0m");
    }
    buf_appendf(&frame, "\x1b[%d;1H\x1b[2K", g_term_rows - 1);
    rule_buf(&frame, 0);
    buf_appendf(&frame, "\x1b[%d;1H\x1b[2m↑↓ navigate   enter resume   esc close\x1b[0m",
                g_term_rows);
    out_frame_write(frame.p, frame.len);
}

/* Keep the sliding window covering the selection: after a navigation key
 * moved it, or a resize changed how many rows fit. */
static void sess_pick_follow(int sel, int *from, int list_rows, int total)
{
    if (sel < *from)
        *from = sel;
    if (sel >= *from + list_rows)
        *from = sel - list_rows + 1;
    if (*from > total - list_rows)
        *from = total - list_rows;
    if (*from < 0)
        *from = 0;
}

/* Full-screen /resume picker: recent sessions in the alternate screen,
 * arrows move with wrap, enter resumes, esc cancels. Returns 1 and
 * fills path on a pick, 0 on cancel, -1 when there is nothing to list. */
static int session_pick(char *path, size_t cap)
{
    struct sess_row *rows = xmalloc(sizeof(struct sess_row) * 64);
    char (*paths)[MAX_PATH] = xmalloc(sizeof(*paths) * 64);
    int all = 0;
    int total = session_list(paths, 64, &all);
    if (!total) {
        free(paths);
        free(rows);
        return -1;
    }
    for (int i = 0; i < total; i++) {
        memcpy(rows[i].path, paths[i], MAX_PATH);
        const char *base = strrchr(paths[i], '\\');
        base = base ? base + 1 : paths[i];
        sess_age_of(base, rows[i].age, sizeof rows[i].age);
        sess_scan_file(&rows[i]);
    }
    free(paths);

    DWORD saved;
    /* raw VT bytes like the composer: Ctrl+C lands as a key (cancel),
     * QuickEdit stays on for mouse selection */
    if (!term_raw_begin(&saved)) {
        free(rows);
        return 0;
    }

    int sel = 0, from = 0;
    int list_rows = g_term_rows - 4;
    if (list_rows > total)
        list_rows = total;
    if (list_rows < 1)
        list_rows = 1;
    /* reset the dock's scroll region, take over the screen, clear once;
     * the picker paints raw (full-screen overlay, no content seeking) */
    g_no_seek = 1;
    out_puts("\x1b[r\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
    int leave = 0, picked = 0, dirty = 1;
    /* raw VT bytes like the composer: arrows arrive as ESC [ A/B … */
    while (!leave) {
        if (dirty) {
            sess_pick_draw(rows, total, all, from, sel, list_rows);
            dirty = 0;
        }
        unsigned char b;
        if (!term_wait_readable(200)) {
            /* idle: pick up terminal resizes between keystrokes */
            term_size_refresh();
            int lr = g_term_rows - 4;
            if (lr > total)
                lr = total;
            if (lr < 1)
                lr = 1;
            if (lr != list_rows) {
                list_rows = lr;
                sess_pick_follow(sel, &from, list_rows, total);
                out_puts("\x1b[2J\x1b[H"); /* relayout: wipe stale rows */
                dirty = 1;
            }
            continue;
        }
        int rr = term_read_byte(&b);
        if (rr < 0)
            break;    /* input closed */
        if (rr == 0)
            continue; /* Ctrl+Z EOF mark: nothing to undo here */
        if (b == 0x1B) {
            unsigned char s;
            if (term_read_byte_timeout(&s, 50) <= 0) {
                leave = 1; /* lone esc: cancel */
                break;
            }
            if (s == '[' || s == 'O') {
                char params[16];
                size_t np;
                unsigned char final = csi_read(params, sizeof params, &np);
                if (!final)
                    continue;
                if (final == 'A')
                    sel = sel > 0 ? sel - 1 : total - 1;
                else if (final == 'B')
                    sel = sel + 1 < total ? sel + 1 : 0;
                else if (final == 'H')
                    sel = 0;
                else if (final == 'F')
                    sel = total - 1;
                else if (final == '~' && np == 1 && params[0] == '5')
                    sel = sel > list_rows ? sel - list_rows : 0;
                else if (final == '~' && np == 1 && params[0] == '6')
                    sel = sel + list_rows < total ? sel + list_rows
                                                  : total - 1;
                else
                    continue;
                sess_pick_follow(sel, &from, list_rows, total);
                dirty = 1; /* a navigation key moved the selection */
            }
            /* meta chords and other escapes: ignored */
            continue;
        }
        if (b == '\r' || b == '\n') {
            picked = 1;
            leave = 1;
        } else if (b == 'q' || b == 0x03) {
            leave = 1; /* q / Ctrl+C cancel */
        }
    }
    out_puts("\x1b[?25h\x1b[?1049l");
    g_no_seek = 0;
    term_raw_end(saved);
    if (picked) {
        snprintf(path, cap, "%s", rows[sel].path);
        free(rows);
        return 1;
    }
    free(rows);
    return 0;
}

/* --- slash commands ------------------------------------------------------ */

static int agent_loop(struct config *cfg, struct conversation *cv,
                      struct session_log *slog, const char *system_prompt,
                      int auto_compact);

static const char KK_SYSTEM_PROMPT[] =
    "You are kk, a concise terminal coding agent running on Windows in "
    "PowerShell. Work in the user's language. Locate code with find (file "
    "names or glob patterns) or grep (contents; a query like '*.ext term' "
    "filters by file) when the path is unknown, read before "
    "changing anything, change files with the write tool (pass old_string "
    "for precise replacements, copying text exactly from the read output), "
    "and verify changes by running commands with the bash tool, which takes "
    "a whole script: chain independent commands with ';' in ONE call instead "
    "of spending a call each. Batch "
    "ruthlessly: decide everything you need before acting and emit it as "
    "ONE round of parallel calls — 3 or more calls per round is the norm "
    "and a single call in a round is a defect, because every extra round "
    "re-sends the whole context and costs seconds. Split into another "
    "round only when a call's arguments need an earlier call's result. "
    "Keep answers short and factual";

/* The session-stable system prompt: base text plus the AGENTS.md hierarchy,
 * root-first. Returns a heap string. */
/* A workspace snapshot: the model otherwise spends a whole round (~3 s and a
 * full context resend) discovering the tree. fff answers that from a warm
 * index in well under a millisecond, ranked by what this project opens most.
 * The listing is capped so a deep tree cannot inflate every later round. */
#define SNAPSHOT_MAX 2048
static char *workspace_snapshot(void)
{
    if (!fff_ensure())
        return NULL; /* no index: fall back to the model exploring */
    struct arena a;
    arena_init(&a, 512);
    struct jnode *args = json_parse(&a, "{}", 2);
    /* an argument-less find is the list mode; it skips fff.track, so seeding
     * the prompt never skews the ranking it reads */
    char *listing = args ? tool_find(args, NULL) : NULL;
    arena_free(&a);
    if (!listing || strncmp(listing, "error:", 6) == 0) {
        free(listing);
        return NULL;
    }
    struct buf b = BUF_INIT;
    buf_appends(&b, "\n\n# Workspace snapshot\n\n");
    /* The listing is relative and nothing else in the prompt says where the
     * agent is, so a model that wants an absolute path invents one: a real
     * run read C:\code\test2\help.md — a directory that does not exist on
     * this machine — and spent the next whole round (2,895 input tokens)
     * discovering its own working directory. */
    char cwd[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, cwd))
        buf_appendf(&b,
                    "Working directory: %s\n"
                    "Pass paths relative to it, exactly as listed below: never "
                    "prefix a directory you invented.\n\n",
                    cwd);
    buf_appends(&b,
                "Most-touched files here at startup, with sizes and git "
                "status. Do not spend a round listing the directory: read "
                "from this, and use find/grep only for what is missing.\n\n");
    size_t used = 0;
    for (char *p = listing, *nl; p && *p && used < SNAPSHOT_MAX; p = nl) {
        nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        buf_append_n(&b, p, n);
        buf_appendc(&b, '\n');
        used += n + 1;
        if (!nl)
            break;
        nl++;
    }
    free(listing);
    return buf_detach(&b);
}

/* Every round re-pays the static head: one
 * project's AGENTS.md measured 22.9KB ≈ 6.8k tokens per round. Sizes are
 * what actually got appended (section headers included), pre-escape; the
 * wire adds a few percent. Printed once per interactive session, right
 * where the prompt is first built, so the number lands before that round. */
#define HEAD_BYTES_PER_TOKEN 3.4 /* median req / prompt_tokens over logs */
static const struct buf *tools_json_block(void);
static void head_report(size_t agents, size_t skills, size_t snap)
{
    size_t base = sizeof(KK_SYSTEM_PROMPT) - 1;
    size_t tools = tools_json_block()->len;
    size_t head = base + agents + skills + snap + tools;
    char line[224];
    snprintf(line, sizeof line,
             "静态头 %.1fKB ≈ %.1fk token/轮 · tools %.1f + AGENTS.md %.1f + "
             "基础 %.1f + skills %.1f + 快照 %.1f",
             head / 1024.0, head / (HEAD_BYTES_PER_TOKEN * 1024.0),
             tools / 1024.0, agents / 1024.0, base / 1024.0, skills / 1024.0,
             snap / 1024.0);
    out_printf(vt_or("\x1b[2m%s\x1b[0m\r\n", "%s\r\n"), line);
}

static char *system_prompt_build(int report)
{
    struct buf b = BUF_INIT;
    buf_appends(&b, KK_SYSTEM_PROMPT);
    size_t from = b.len; /* each section's bytes are the next b.len - from */
    char *agents = load_agents_md();
    if (agents) {
        buf_appends(&b, "\n\n# Project instructions (AGENTS.md)\n");
        buf_appends(&b, agents);
        free(agents);
    }
    size_t agents_n = b.len - from;
    from = b.len;
    char *skills = load_skills();
    if (skills) {
        buf_appends(&b, "\n\n");
        buf_appends(&b, skills);
        free(skills);
    }
    size_t skills_n = b.len - from;
    from = b.len;
    char *snap = workspace_snapshot();
    if (snap) {
        buf_appends(&b, snap);
        free(snap);
    }
    if (report)
        head_report(agents_n, skills_n, b.len - from);
    return buf_detach(&b);
}

/* section 10: folds history into a summary (defined in the agent part) */
static int conv_compact(struct config *cfg, struct conversation *cv,
                        struct session_log *slog);

/* section 9 REPL: the startup banner (reused by /new / /resume resets) */
static void repl_banner(void);

/* The tail every /resume path shares: switch and replay on success, or
 * fall back to a fresh session when the log will not load. Silent on the
 * internals — the caller owns the notice's exact wording. */
static void resume_finish(struct session_log *slog, struct conversation *cv,
                          const char *path)
{
    if (session_switch(slog, cv, path) == 0) {
        session_reset_screen();
        conv_replay(cv);
        if (g_emit_vt)
            out_printf("\x1b[2m已切换到会话 %s（%zu 条消息）\x1b[0m\r\n",
                       path, cv->msgs.n);
        else
            out_printf("已切换到会话 %s（%zu 条消息）\r\n", path, cv->msgs.n);
    } else {
        session_reset_screen();
        repl_banner();
        out_puts("会话读取失败，已开启新会话\r\n");
    }
}

static int cmd_slash(struct config *cfg, const char *line,
                     struct conversation *cv, struct session_log *slog)
{
    const char *sp = strchr(line, ' ');
    size_t nlen = sp ? (size_t)(sp - line) : strlen(line);
    char name[32];
    if (nlen >= sizeof name)
        nlen = sizeof name - 1;
    memcpy(name, line, nlen);
    name[nlen] = '\0';
    const char *arg = sp ? sp + 1 : "";

    if (strcmp(name, "/new") == 0) {
        conv_truncate(cv, 0);
        session_close(slog);
        session_open(slog, 0, cv);
        /* ki's transition: terminal reset, then the screen reads like
         * the first launch — banner, empty transcript */
        session_reset_screen();
        repl_banner();
        return 1;
    }
    if (strcmp(name, "/skills") == 0) {
        /* exactly the block the system prompt carries, so what you read
         * here is what the model is offered */
        char *s = load_skills();
        if (!s) {
            out_puts("没有可列出的 skill：在 %USERPROFILE%\\.agents\\skills"
                     " 或 <工作区>\\.agents\\skills 下放 <名字>\\SKILL.md\r\n");
            return 1;
        }
        for (char *p = s, *nl; p && *p; p = nl ? nl + 1 : NULL) {
            nl = strchr(p, '\n');
            out_printf("%.*s\r\n", nl ? (int)(nl - p) : (int)strlen(p), p);
        }
        free(s);
        return 1;
    }
    if (strcmp(name, "/resume") == 0) {
        if (!*arg && g_console_in && g_emit_vt) {
            /* interactive: the full-screen picker */
            char pick[MAX_PATH];
            int got = session_pick(pick, sizeof pick);
            if (got > 0)
                resume_finish(slog, cv, pick);
            else if (got == 0)
                out_puts("已取消\r\n");
            else
                out_puts("还没有可切换的会话\r\n");
            return 1;
        }
        if (!*arg) {
            /* scripted stdin: plain numbered list */
            char (*paths)[MAX_PATH] = xmalloc(sizeof(*paths) * 64);
            int n = session_list(paths, 64, NULL);
            out_printf("最近的会话（%d）\r\n", n);
            for (int i = 0; i < n; i++) {
                const char *base = strrchr(paths[i], '\\');
                base = base ? base + 1 : paths[i];
                out_printf("  %d. %.4s-%.2s-%.2s %.2s:%.2s:%.2s  (%s)\r\n",
                           i + 1, base, base + 4, base + 6, base + 9,
                           base + 11, base + 13, base);
            }
            out_puts("/resume <编号> 切换\r\n");
            free(paths);
            return 1;
        }
        int pick = atoi(arg);
        char (*paths)[MAX_PATH] = xmalloc(sizeof(*paths) * 64);
        int n = session_list(paths, 64, NULL);
        if (pick < 1 || pick > n) {
            out_printf("无效的会话编号（1-%d）\r\n", n);
            free(paths);
            return 1;
        }
        resume_finish(slog, cv, paths[pick - 1]);
        free(paths);
        return 1;
    }
    if (strcmp(name, "/compact") == 0) {
        conv_compact(cfg, cv, slog);
        return 1;
    }
    out_printf("未知命令 %s\r\n", name);
    return 1;
}

/* --- REPL ---------------------------------------------------------------- */

static void repl_banner(void)
{
    if (g_emit_vt)
        out_printf("\x1b[1mkk\x1b[0m %s \x1b[2m· Ctrl+D 退出\x1b[0m\r\n\r\n",
                   KK_VERSION);
    else
        out_printf("kk %s · Ctrl+D 退出\r\n\r\n",
                   KK_VERSION);
}

/* Agent turn thread: one live turn at a time, while the composer keeps
 * the main thread for the whole session. goal != NULL runs /goal's
 * autonomous loop instead of a single turn. */
struct agent_args {
    struct config *cfg;
    struct conversation *cv;
    struct session_log *slog;
    const char *sysp;
    char *goal;
};
static HANDLE g_agent_thread;

static int goal_loop(struct config *cfg, struct conversation *cv,
                     struct session_log *slog, const char *system_prompt,
                     const char *task);

static DWORD WINAPI agent_thread_proc(LPVOID arg)
{
    struct agent_args *a = arg;
    if (a->goal) {
        goal_loop(a->cfg, a->cv, a->slog, a->sysp, a->goal);
        free(a->goal);
    } else {
        agent_loop(a->cfg, a->cv, a->slog, a->sysp, 1);
    }
    out_printf_thread_end();
    nap_thread_end(); /* this thread ran the tools, and napped in them */
    free(a);
    return 0;
}

/* Start a turn on the agent thread: goal == NULL runs one turn, goal != NULL
 * runs the /goal loop with that task as its first user turn. Both dispatch
 * sites used to fill these five fields by hand, and the ordinary-turn one never
 * set `goal` — xmalloc does not zero, so agent_thread_proc's `if (a->goal)`
 * branched on whatever the recycled chunk held (a -1 from an old handle is the
 * usual guest) and jumped into goal_loop with a bogus task pointer. One place
 * to add a field, one place that cannot forget it. */
static void agent_start(struct config *cfg, struct conversation *cv,
                        struct session_log *slog, const char *sysp,
                        const char *goal)
{
    if (g_agent_thread)
        CloseHandle(g_agent_thread); /* previous turn, reaped */
    struct agent_args *aa = xmalloc(sizeof *aa);
    aa->cfg = cfg;
    aa->cv = cv;
    aa->slog = slog;
    aa->sysp = sysp;
    aa->goal = goal ? xstrdup(goal) : NULL;
    g_agent_thread = CreateThread(NULL, 0, agent_thread_proc, aa, 0, NULL);
    if (g_agent_thread)
        return;
    /* no thread available: run it right here. The goal path still owns the
     * task text as a user turn; the queued text of a normal turn still feeds
     * through turn_feed_queue. */
    free(aa->goal);
    free(aa);
    if (goal)
        goal_loop(cfg, cv, slog, sysp, goal);
    else
        agent_loop(cfg, cv, slog, sysp, 1);
}

/* Queue one line as pending user input (turn start or mid-turn steer). */
static void queue_user_line(const char *line)
{
    AcquireSRWLockExclusive(&g_out_lock);
    buf_append_n(&g_queued, line, strlen(line));
    buf_appendc(&g_queued, '\n');
    ReleaseSRWLockExclusive(&g_out_lock);
}

static int run_repl(struct config *cfg)
{
    /* input dock: the composer panel pins to the bottom edge (rules +
     * draft window + hint + status, 4..13 rows tall) and stays visible
     * for the whole session; output scrolls inside rows 1..N-13. */
    int dock = g_console_in && g_emit_vt;
    int dock_row = 0;
    g_dock = dock;
    g_status_model = xstrdup(cfg->model ? cfg->model : "");
    if (dock) {
        term_size_refresh();
        dock_row = g_term_rows;
        /* the transcript must start at viewport row 1: the scroll region
         * (DECSTBM) is viewport-relative, so old pane content above the
         * session would put the content end outside the region and
         * streaming would plow straight through the panel. 3J wipes the
         * scrollback too — a fresh session owns the whole pane. The
         * region itself is owned by edit_render (tracks panel height). */
        out_puts("\x1b[H\x1b[2J\x1b[3J");
        /* seed the region before the banner so the very first write
         * bottom-aligns exactly like every later one (idle panel: 2 rules +
         * 1 draft row + status = 4 rows) */
        g_region_bottom = g_term_rows - 4;
        out_frame_printf("\x1b[1;%dr", g_region_bottom);
    }

    repl_banner();
    if ((!cfg->model || !*cfg->model) && (!cfg->api_key || !*cfg->api_key)) {
        out_printf(
            "首次使用：设置 KK_BASE_URL / KK_API_KEY / KK_MODEL 环境变量，\r\n"
            "或编辑配置文件 %s\\config\r\n",
            g_appdata_dir);
    }

    struct conversation cv;
    conv_init(&cv);
    struct session_log slog;
    session_open(&slog, 0, &cv);

    struct editor ed;
    editor_init(&ed);

    /* the system prompt is stable for the session: build once, not per turn.
     * Built on first need rather than here, because it waits on fff's warmup
     * lock — doing it at startup would hold up the banner on a large tree. */
    char *sysp = NULL;
    for (;;) {
        char *line = NULL;
        enum edit_result er;
        if (dock) {
            term_size_refresh();
            dock_row = g_term_rows; /* re-anchor after a resize */
            /* the composer panel owns the docked bottom rows */
            er = edit_line(&ed, &line);
        } else if (g_console_in) {
            out_puts("> ");
            er = edit_line(&ed, &line);
        } else {
            /* piped stdin: plain line reading for scripting/tests */
            char tmp[8192];
            out_puts("> ");
            if (!fgets(tmp, sizeof tmp, stdin)) {
                er = EDIT_EOF;
            } else {
                tmp[strcspn(tmp, "\r\n")] = '\0';
                line = xstrdup(tmp);
                er = EDIT_LINE;
            }
        }

        if (er == EDIT_EOF) {
            if ((int)g_busy != 0) {
                /* quit mid-turn: plain cancel, then wait for the agent */
                InterlockedExchange(&g_steer, 0);
                InterlockedExchange(&g_cancel, 1);
                if (g_agent_thread) {
                    WaitForSingleObject(g_agent_thread, INFINITE);
                    CloseHandle(g_agent_thread);
                    g_agent_thread = NULL;
                }
                if (g_emit_vt)
                    out_frame_puts("\x1b[?25h");
            }
            out_puts("bye\r\n");
            break;
        }
        if (er == EDIT_CANCEL)
            continue;
        if (!line || !*line) {
            free(line);
            continue;
        }

        /* history (skip commands) */
        if (line[0] != '/') {
            char *copy = xstrdup(line);
            DA_PUSH(ed.history, copy);
        }

        if (!sysp)
            sysp = system_prompt_build(1); /* first submission: by now fff's
                                           * warmup has finished on its own */

        if ((int)g_busy != 0) {
            /* mid-turn: text steers — it interrupts the run and drives
             * the next request; slash commands wait (they touch session
             * state the turn owns) */
            if (line[0] == '/') {
                out_puts(
                    "\x1b[2m回合进行中：命令请先 Ctrl+C 打断再执行\x1b[0m\r\n");
            } else {
                queue_user_line(line);
                InterlockedExchange(&g_steer, 1);
                InterlockedExchange(&g_cancel, 1);
            }
        } else if (line[0] == '/' && strncmp(line, "/goal", 5) == 0
                   && (line[5] == '\0' || line[5] == ' ')) {
            /* /goal <task>: autonomous rounds until ✅, a budget, or the
             * human. goal_loop owns the task text as its first user turn. */
            const char *task = line + 5;
            while (*task == ' ')
                task++;
            if (!*task) {
                out_puts("用法：/goal <任务描述>（自主连续推进；完成时以 ✅ "
                         "收尾；Ctrl+C 随时中止）\r\n");
            } else if (!cfg->model || !*cfg->model) {
                out_printf("未设置模型：请设置 KK_MODEL 或在 %s\\config 里配置\r\n",
                           g_appdata_dir);
            } else if (dock) {
                agent_start(cfg, &cv, &slog, sysp, task);
            } else {
                /* non-dock console: synchronous goal */
                goal_loop(cfg, &cv, &slog, sysp, task);
            }
        } else if (line[0] == '/') {
            cmd_slash(cfg, line, &cv, &slog);
            session_flush(&slog); /* /compact logs outside agent_loop */
        } else if (!cfg->model || !*cfg->model) {
            out_printf("未设置模型：请设置 KK_MODEL 或在 %s\\config 里配置\r\n",
                       g_appdata_dir);
        } else if (dock) {
            /* start a turn on the agent thread: the text feeds through
             * g_queued (turn_feed_queue echoes it as the cyan bars) and
             * the composer keeps running right here */
            queue_user_line(line);
            agent_start(cfg, &cv, &slog, sysp, NULL);
        } else {
            /* non-dock console: synchronous turn */
            struct message *um = conv_add(&cv, "user", line);
            attach_user_images(um, line);
            session_log_message(&slog, um);
            agent_loop(cfg, &cv, &slog, sysp, 1);
        }
        free(line);
    }

    free(sysp);
    editor_free(&ed);
    session_close(&slog);
    conv_free(&cv);
    if (dock) {
        out_frame_puts("\x1b[r"); /* release the scroll region */
        if (dock_row > 0)
            out_frame_printf("\x1b[%d;1H", dock_row);
        out_frame_puts("\r\n");
    }
    g_dock = 0;
    return 0;
}

/* ==========================================================================
 * 10. agent — turn loop + wmain
 * ========================================================================== */

/* --- request serialization --------------------------------------------- */

/* Request-JSON for one message. Messages are immutable once queued, so the
 * escaped fragment is cached: a long tool loop re-serializes only the new
 * tail instead of re-escaping the whole (file-laden) history every round. */
static void msg_append_json(struct buf *b, struct message *m)
{
    if (!m->json_cache) {
        struct buf j = BUF_INIT;
        msg_serialize(&j, m, 1);
        m->json_cache_len = j.len;
        m->json_cache = buf_detach(&j);
    }
    /* append by length: a strlen over every cached fragment would scan the
     * whole request body once per round */
    buf_append_n(b, m->json_cache, m->json_cache_len);
}

/* Extract a user-facing message from an API error body: prefers
 * {"error":{"message":..}}, then {"message":..}, else the raw body. */
static char *api_error_message(const char *body)
{
    struct arena a;
    arena_init(&a, 4096);
    char *out = NULL;
    struct jnode *v = json_parse(&a, body, strlen(body));
    if (v && v->tag == J_OBJ) {
        struct jnode *e = jobj_get(v, "error");
        if (e && e->tag == J_OBJ)
            e = jobj_get(e, "message");
        if (e && e->tag == J_STR) {
            struct buf b = BUF_INIT;
            jdecode_str(e->raw, &b);
            out = buf_detach(&b);
        }
    }
    arena_free(&a);
    if (!out) {
        struct str raw = str_from_c(body);
        while (raw.n > 0 && (raw.p[raw.n - 1] == '\n' || raw.p[raw.n - 1] == '\r'
                             || raw.p[raw.n - 1] == ' '))
            raw.n--;
        out = raw.n ? str_dupz(raw) : xstrdup("unknown API error");
    }
    return out;
}

/* The serialized `tools` array: a compile-time constant, escaped once. Also
 * read by the startup head report — every round pays this bytes-per-request. */
static const struct buf *tools_json_block(void)
{
    static struct buf b;
    if (!b.len) {
        for (size_t ti = 0; ti < KK_N_TOOLS; ti++) {
            if (ti)
                buf_appends(&b, ",");
            buf_appends(&b, "{\"type\":\"function\",\"function\":{\"name\":\"");
            buf_appends(&b, KK_TOOLS[ti].name);
            buf_appends(&b, "\",\"description\":\"");
            json_escape_append(&b, KK_TOOLS[ti].description,
                               strlen(KK_TOOLS[ti].description));
            buf_appends(&b,
                        "\",\"parameters\":{\"type\":\"object\",\"properties\":");
            buf_appends(&b, KK_TOOLS[ti].params);
            buf_appends(&b, "}}}");
        }
    }
    return &b;
}

/* One model round-trip: POST and stream into hooks. Returns HTTP status,
 * 0 on a transport error, or -1 when cancelled. st carries the result.
 * (cv is non-const: serialization caches fragments on the messages.) */
static int chat_stream(struct config *cfg, struct conversation *cv,
                       const char *system_prompt, int with_tools,
                       const struct stream_hooks *hooks,
                       struct stream_state *st)
{
    /* pre-size from the last request: a long conversation otherwise pays
     * ~10 doubling reallocs (each copying the whole body) every round. The
     * previous body itself survives below as the prefix-cache baseline, so
     * its length doubles as the size hint — no separate counter needed. */
    static struct buf prev_body;
    struct buf body = BUF_INIT;
    buf_reserve(&body, prev_body.len + 4096);
    buf_appends(&body, "{\"model\":\"");
    json_escape_append(&body, cfg->model, strlen(cfg->model));
    if (with_tools) {
        /* The tool schema block sits AHEAD of `messages` on purpose. Prompt
         * caching is a *prefix* cache, and every round appends inside the
         * messages array: last in the body these kilobytes of unchanging
         * text could never fall inside a shared prefix. JSON key order
         * carries no meaning for the API, only for the byte-level prefix. */
        const struct buf *tj = tools_json_block();
        buf_appends(&body, "\",\"tools\":[");
        buf_append_n(&body, tj->p, tj->len);
    }
    buf_appends(&body, with_tools ? "],\"messages\":[" : "\",\"messages\":[");
    int first = 1;
    if (system_prompt && *system_prompt) {
        /* the escaped system fragment is cached per source pointer: the
         * REPL builds it once per session and retries re-use it too */
        static struct buf sys_json;
        static const char *sys_src;
        if (sys_src != system_prompt) {
            buf_reset(&sys_json);
            buf_appends(&sys_json, "{\"role\":\"system\",\"content\":\"");
            json_escape_append(&sys_json, system_prompt, strlen(system_prompt));
            buf_appends(&sys_json, "\"}");
            sys_src = system_prompt;
        }
        buf_append_n(&body, sys_json.p, sys_json.len);
        first = 0;
    }
    for (size_t i = 0; i < cv->msgs.n; i++) {
        if (!first)
            buf_appends(&body, ",");
        first = 0;
        msg_append_json(&body, &cv->msgs.p[i]);
    }
    buf_appendf(&body,
                "],\"stream\":true,\"max_tokens\":%lld,"
                "\"stream_options\":{\"include_usage\":true}}",
                /* Without a ceiling a degenerate repetition loop bills
                 * unbounded output and then sits in the session log forever:
                 * one captured run put 757,988 characters (~190k tokens, 98%
                 * the same sentence) into one assistant message. The default
                 * keeps ~3x headroom over writing a 40KB file, whose content
                 * also counts as output. */
                (long long)env_i64("KK_MAX_OUTPUT_TOKENS", 1, 32768));

    struct chat_request cr;
    memset(&cr, 0, sizeof cr);
    cr.st = st;
    cr.hooks = *hooks;
    arena_init(&cr.arena, 64 * 1024);

    /* join base_url + endpoint once per process: base_url is fixed at
     * startup, and every round — plus every compaction request — used to
     * rebuild and free this string */
    static char *s_url;
    static char *s_url_src;
    if (!s_url_src || strcmp(s_url_src, cfg->base_url) != 0) {
        size_t blen = strlen(cfg->base_url);
        while (blen > 0 && cfg->base_url[blen - 1] == '/')
            blen--;
        char *fresh = xasprintf("%.*s/chat/completions", (int)blen,
                                cfg->base_url);
        if (fresh) {
            free(s_url);
            free(s_url_src);
            s_url = fresh;
            s_url_src = xstrdup(cfg->base_url);
        }
    }

    char *err_body = NULL;
    st->request_bytes = body.len;
    /* KK_DUMP_REQ=<path>: write the exact bytes we are about to send. The
     * session log records messages, not the serialized request, so a gap
     * between `req` and the sum of the logged messages cannot be closed
     * without this. Overwrites: the file is always the current request. */
    {
        static char *dump_path;
        static int dumped_probe;
        if (!dumped_probe) {
            dumped_probe = 1;
            dump_path = env_get("KK_DUMP_REQ");
        }
        if (dump_path && *dump_path)
            file_write_all(str_from_c(dump_path), body.p, body.len);
    }
    /* prefix-cache diagnostics: how much of this request repeats the
     * previous one byte-for-byte from the very first byte. A small `shared`
     * on a big body is our own instability; a big `shared` with
     * `cache_tokens` still 0 is the endpoint's. */
    {
        size_t cmp = body.len < prev_body.len ? body.len : prev_body.len;
        size_t sh = 0;
        st->request_prev = prev_body.len != 0;
        /* 16 bytes at a time: bodies run to megabytes and the shared prefix
         * is normally the whole of everything but the new tail */
#if defined(_M_X64)
        while (sh + 16 <= cmp) {
            __m128i a = _mm_loadu_si128((const __m128i *)(body.p + sh));
            __m128i b = _mm_loadu_si128((const __m128i *)(prev_body.p + sh));
            if (_mm_movemask_epi8(_mm_cmpeq_epi8(a, b)) != 0xFFFF)
                break;
            sh += 16;
        }
#endif
        while (sh < cmp && body.p[sh] == prev_body.p[sh])
            sh++;
        st->request_shared = sh;
    }
    int status = http_post_stream(s_url, cfg->api_key, body.p, body.len, 10000,
                                  120000, sse_on_bytes, &cr, &err_body);
    if (status == 0 && err_body) {
        st->error = err_body; /* transport failure text */
        err_body = NULL;
    } else if (status >= 400 && err_body) {
        st->error = api_error_message(err_body);
        st->finish = FINISH_ERROR;
    } else if (status == -1) {
        st->finish = FINISH_ERROR;
    }
    free(err_body);

    /* A 200 that carried no event, no finish_reason and no usage chunk is a
     * provider that accepted the request and closed the response without
     * answering. Nothing streamed, so report it as a transport failure and
     * let the caller's backoff retry — a replay duplicates nothing on
     * screen, and a dead turn otherwise ends with no reply and no error. */
    if (status == 200 && st->finish == FINISH_NONE && !st->got_usage
        && !st->content.len && !st->reasoning.len && !st->n_calls) {
        free(st->error);
        st->error = xstrdup("connection closed before any data");
        status = 0;
    }

    /* the diagnostic above already consumed the previous body: keep THIS
     * one for the next round by moving it, not copying it — one full body
     * resident at a time, and its length pre-sizes the next round's build */
    buf_free(&prev_body);
    prev_body = body;
    body = (struct buf)BUF_INIT; /* ownership moved: nothing may free it twice */

    sse_parser_free(&cr.sse);
    arena_free(&cr.arena);
    return status;
}

/* --- context compaction --------------------------------------------------- */

/* Case-insensitive substring search (ASCII): provider error texts vary
 * in wording and casing. */
static int ci_contains(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    for (; *hay; hay++)
        if (_strnicmp(hay, needle, n) == 0)
            return 1;
    return 0;
}

/* Does an API error text mean the request exceeded the context window?
 * Every provider words it differently; match the common shapes. */
static int error_is_context_overflow(const char *err)
{
    static const char *const marks[] = {
        "context length", "context_length", "maximum context",
        "context window", "too many tokens", "input length",
    };
    for (size_t i = 0; i < sizeof marks / sizeof marks[0]; i++)
        if (ci_contains(err, marks[i]))
            return 1;
    return 0;
}

/* Assumed context window in tokens: KK_CONTEXT_WINDOW over a 256k default.
 * Corrected downward at runtime when an overflow rejection tells us the real
 * limit — guessing high is only safe because that correction exists. */
static int64_t g_window_tokens;

static int64_t compact_window_tokens(void)
{
    if (!g_window_tokens)
        g_window_tokens = env_i64("KK_CONTEXT_WINDOW", 1, 262144);
    return g_window_tokens;
}

/* Adopt a limit learned from an error, only if it is smaller than what we
 * assumed and not absurd. Returns 1 when the window changed. */
static int adopt_window_tokens(int64_t v)
{
    if (v < 1024 || v >= compact_window_tokens())
        return 0;
    g_window_tokens = v;
    return 1;
}

/* Smallest plausible token count in an overflow message. Providers word
 * these differently and several quote the requested size before the limit,
 * but the limit is always below what we just assumed while the requested
 * size is above it — so the minimum wins. */
static int64_t parse_context_limit(const char *err)
{
    int64_t best = 0;
    for (const char *p = err; *p; p++) {
        if (*p < '0' || *p > '9')
            continue;
        int64_t v = str_to_i64(&p);
        p--;
        if (v >= 1024 && v < compact_window_tokens() && (!best || v < best))
            best = v;
    }
    return best;
}

/* Index of the last message carrying this role, or cv->msgs.n when there is
 * none. Recycling, stubbing and compaction each ask this walking back from
 * the tail, so the walk exists once. */
static size_t conv_rfind(const struct conversation *cv, const char *role)
{
    for (size_t i = cv->msgs.n; i > 0; i--)
        if (strcmp(cv->msgs.p[i - 1].role, role) == 0)
            return i - 1;
    return cv->msgs.n;
}

/* Replace bulky tool output with a short visible stub. One walk, three
 * settings, because the walk is the only interesting part:
 *
 *   routine recycling (min_bytes = TOOL_STUB_MIN, min_rounds = TOOL_KEEP_ROUNDS)
 *     runs before every request: a result the model has already had min_rounds
 *     requests to use is re-paid forever otherwise (corpus numbers: re-sent
 *     history is 26x the generated text, one 49-round turn paid 1.0M tokens
 *     mostly from 20-60KB read results it had stopped looking at). The slack
 *     guarantees the model never loses output it has not seen, and anything
 *     recycled is one call away from being fetched back.
 *
 *   overflow recovery (0, 0, keep_last) runs when the whole history IS the
 *     current turn, so there is no head to fold: every tool output before the
 *     last one goes and the freshest stays verbatim. Those stubs are transient
 *     for the retried request: the session log already holds the real output
 *     it recorded, and the screen showed it live.
 *
 * Returns 1 when something was stubbed and, if freed is given, reports the
 * bytes it took out of what the next request carries. */
static int conv_stub_tool_results(struct conversation *cv, size_t *freed,
                                  size_t min_bytes, size_t min_rounds,
                                  int keep_last)
{
    size_t last = conv_rfind(cv, "tool");
    if (last == cv->msgs.n)
        return 0; /* no tool output at all */
    int n_tools = 0;
    for (size_t i = 0; i <= last; i++)
        if (strcmp(cv->msgs.p[i].role, "tool") == 0)
            n_tools++;
    if (!n_tools)
        return 0;

    int n = 0;
    size_t bytes = 0, rounds = 0; /* requests that already carried it */
    for (size_t i = cv->msgs.n; i > 0; i--) {
        struct message *m = &cv->msgs.p[i - 1];
        if (strcmp(m->role, "assistant") == 0) {
            rounds++;
            continue;
        }
        if (i - 1 > last || strcmp(m->role, "tool") != 0 || !m->content)
            continue;
        if (keep_last && i - 1 == last && n_tools > 1)
            continue; /* with older outputs to stub, the freshest one stays */
        if (rounds < min_rounds)
            continue;
        size_t len = strlen(m->content);
        if (len <= min_bytes)
            continue; /* too small to be worth re-running the call for */
        free(m->content);
        /* The first stub of a pass carries the reason. The model has no other
         * way to learn its context was trimmed — the ♻ line goes to the screen,
         * not the conversation — so without this it keeps reading whole files
         * and rides the context down into the overflow retry. One clause, once
         * per pass, riding on an existing tool message: a synthetic user turn
         * would read as the human speaking and hand control back in /goal. */
        m->content = xasprintf("[tool output recycled: %zu bytes — re-run "
                               "the call above to fetch it again%s]", len,
                               n ? ""
                                 : "; context trimmed to fit — prefer narrow "
                                   "offset/limit reads from here on");
        free(m->json_cache); /* the cached fragment still holds the full
                              * output: it must go with the content */
        m->json_cache = NULL;
        bytes += len;
        n++;
    }
    if (!n)
        return 0;
    if (freed)
        *freed = bytes;
    /* per-round aging frees a bit every round: only a real saving is worth a
     * line on screen */
    if (bytes >= 8192)
        out_printf("♻ %d 条较早的工具输出（共 %zu 字节）换成占位，"
                   "重跑调用即可取回\r\n", n, bytes);
    return 1;
}

/* Bulky tool results worth recycling, and how many rounds the model gets
 * to use them first. Sizes are bytes; tokens are roughly half. */
#define TOOL_STUB_MIN 2048
#define TOOL_KEEP_ROUNDS 2

/* Fold everything before the most recent user turn into one summary
 * message. display == model view: the summary is printed exactly as the
 * model will see it, and the session log records the replacement so
 * --continue restores the same view. History is never destroyed unless
 * the summary request actually succeeded. */
static int conv_compact(struct config *cfg, struct conversation *cv,
                        struct session_log *slog)
{
    /* the tail starts at the last user message: it keeps the current
     * exchange (and its tool traffic) verbatim and is always a safe
     * request boundary — a tail can never begin with an orphan tool
     * result */
    size_t cut = conv_rfind(cv, "user");
    if (cut == 0 || cut == cv->msgs.n) {
        out_puts("会话还很短，无需压缩\r\n");
        return 0;
    }

    /* serialize the head for the summarizer, capped at roughly half the
     * context window (≈2 bytes per token in CJK-heavy text), keeping the
     * most recent part */
    int64_t window = compact_window_tokens();
    /* 1.5 bytes per assumed token, not 2: the summarizer's own instruction
     * and its reply need room too, or the request meant to fix an overflow
     * overflows on its own */
    size_t cap = (size_t)((window > 4096 ? window : 4096) * 3 / 2);
    struct buf head = BUF_INIT;
    for (size_t i = 0; i < cut; i++) {
        const struct message *m = &cv->msgs.p[i];
        if (strcmp(m->role, "user") == 0) {
            buf_appends(&head, "用户: ");
            buf_appends(&head, m->content ? m->content : "");
            buf_appends(&head, "\n\n");
        } else if (strcmp(m->role, "assistant") == 0) {
            buf_appends(&head, "助手: ");
            buf_appends(&head, m->content ? m->content : "");
            for (size_t k = 0; k < m->n_calls; k++)
                buf_appendf(&head, "\n→ %s(%s)", m->calls[k].name,
                            m->calls[k].args ? m->calls[k].args : "");
            buf_appends(&head, "\n\n");
        } else {
            buf_appends(&head, "工具结果: ");
            buf_appends(&head, m->content ? m->content : "");
            buf_appends(&head, "\n\n");
        }
    }
    if (head.len > cap) {
        const char *start = head.p + (head.len - cap);
        while (start < head.p + head.len && *start != '\n')
            start++;
        if (start < head.p + head.len)
            start++;
        struct buf trimmed = BUF_INIT;
        buf_appends(&trimmed, "（更早的内容已省略）\n\n");
        buf_append_n(&trimmed, start,
                     (size_t)(head.p + head.len - start));
        buf_free(&head);
        head = trimmed;
    }

    /* one non-tool request writes the summary; nothing paints while it
     * streams (silent hooks), the committed block is shown afterwards */
    struct conversation tmp;
    conv_init(&tmp);
    struct buf ask = BUF_INIT;
    buf_appends(&ask,
                "请把以下编程会话记录压缩为一份摘要，供助手无缝继续工作。"
                "保留：用户的目标与偏好、关键决定、重要文件路径、命令及其"
                "结果、未完成事项。用要点列出，尽量简短。\n\n"
                "=== 会话记录 ===\n");
    buf_appends(&ask, head.p);
    buf_free(&head);
    conv_add_take(&tmp, "user", buf_detach(&ask));

    struct stream_state st;
    stream_state_init(&st);
    struct stream_hooks silent = { NULL, NULL };
    int status = chat_stream(cfg, &tmp,
                             "You are kk's conversation compactor "
                             "(KK-COMPACT). Reply with the summary only.",
                             0, &silent, &st);
    conv_free(&tmp);

    int ok = status == 200 && st.finish == FINISH_STOP && st.content.len
             && !st.error;
    if (!ok) {
        out_printf("⚠ 压缩请求失败（status %d），会话保持不变\r\n", status);
        stream_state_free(&st);
        return 0;
    }

    /* the exact content the model will see from now on */
    struct buf wire = BUF_INIT;
    buf_appends(&wire,
                "〔上下文压缩〕以下是此前对话的摘要，详细消息已省略：\n\n");
    buf_appends(&wire, st.content.p);

    conv_drop_head(cv, cut);
    conv_prepend_user(cv, buf_detach(&wire));
    struct message *sm = &cv->msgs.p[0];
    /* log the prefixed content: the live model view is prefix+summary, and
     * --continue must restore exactly that, not the bare summary */
    session_log_compact(slog, cv->msgs.n - 1, sm->content);
    stream_state_free(&st);

    out_printf("⋯ 上下文已压缩：前 %zu 条消息折叠为摘要，保留最近 %zu 条\r\n",
               cut, cv->msgs.n - 1);
    if (g_emit_vt)
        out_puts("\x1b[2m");
    const char *p = sm->content;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n && p[n - 1] == '\r')
            n--;
        out_printf("┊ %.*s\r\n", (int)n, p);
        p += nl ? (size_t)(nl - p) + 1 : strlen(p);
    }
    if (g_emit_vt)
        out_puts("\x1b[0m");
    return 1;
}

/* Commit whatever text a round produced as the assistant message it was. The
 * stream already painted it, so the conversation must carry it too — display ==
 * model view holds even for a round that was cut short.
 *
 * It deliberately does NOT attach the in-flight tool_calls: calls that did not
 * run would leave the next request holding tool results with no assistant
 * message to own them, which is a 400 the whole session then inherits. */
static void turn_commit_text(struct conversation *cv, struct session_log *slog,
                             struct stream_state *st)
{
    if (!st->content.len)
        return;
    struct message *m = conv_add_take(cv, "assistant", buf_detach(&st->content));
    session_log_message(slog, m);
}

/* Take everything queued, echoing each line as the user turn it
 * becomes, appending to the conversation and the session log, and
 * clearing the pinned block. Main thread only. */
static void turn_feed_queue(struct conversation *cv, struct session_log *slog)
{
    AcquireSRWLockExclusive(&g_out_lock);
    char *take = g_queued.len ? buf_detach(&g_queued) : NULL;
    ReleaseSRWLockExclusive(&g_out_lock);
    /* the steer intent is satisfied once its content is delivered — a
     * leftover flag would turn the next plain Ctrl+C into a steer */
    InterlockedExchange(&g_steer, 0);
    if (!take)
        return;
    for (char *s = take; *s;) {
        char *nl = strchr(s, '\n');
        size_t n = nl ? (size_t)(nl - s) : strlen(s);
        char *line = xstrndup(s, n); /* conv_add takes ownership of a copy */
        user_line_show(line, n);
        struct message *um = conv_add(cv, "user", line);
        attach_user_images(um, line);
        session_log_message(slog, um);
        free(line);
        s += n + (nl ? 1 : 0);
    }
    free(take);
    status_repaint();
}

static int queue_pending(void)
{
    AcquireSRWLockExclusive(&g_out_lock);
    int has = g_queued.len > 0;
    ReleaseSRWLockExclusive(&g_out_lock);
    return has;
}

/* One parallel read-only call: parse + execute on its own thread, filling the
 * slot the agent loop reaps in call order. */
struct para_slot {
    const char *name;
    const char *args_json;
    char *output;
    struct tool_img img;
    char *summary;
    HANDLE th;
    struct arena ta;
};

/* Tools that only look at the workspace. They are the only ones a batch may
 * overlap: each answers independently of the others, none touches the shell
 * session whose cwd and environment are ordered state, and none writes.
 * grep and find belong here because they are the slowest reads in the set —
 * fff gives grep a 2s time budget per call, so three of them in one batch cost
 * 6s serially and 2s in parallel. fff's own locking makes concurrent searches
 * on the shared handle safe (its unsafe-no-lock parameters are documented as
 * ignored: the library serializes internally). */
static int tool_readonly(const char *name)
{
    return strcmp(name, "read") == 0 || strcmp(name, "grep") == 0
        || strcmp(name, "find") == 0;
}

/* Every tool_call in a committed assistant message needs a tool result, or the
 * next request is a 400 that --continue replays for the rest of the session.
 * This fills in the ones that will not run. */
static void turn_stub_rest(struct conversation *cv, struct session_log *slog,
                           struct tool_call_rec *calls, size_t from, size_t to,
                           const char *why)
{
    for (size_t j = from; j < to; j++) {
        struct message *stub = conv_add(cv, "tool", why);
        stub->tool_call_id = xstrdup(calls[j].id);
        session_log_message(slog, stub);
    }
}

/* --- degenerate tool thrash ------------------------------------------- */
/* The same call, verbatim, THRASH_MAX times in one turn. Signatures are copied
 * rather than pointed at, because the argument strings live in conversation
 * messages that compaction may drop mid-turn. Tracking stops once THRASH_BUDGET
 * is spent, which costs the detector nothing in practice: a loop repeats ONE
 * signature, and the first one is always recorded. */
#define THRASH_MAX 3
#define THRASH_BUDGET (256 * 1024)

struct thrash_rec {
    char *name;
    char *args;
    int count;
};
static struct thrash_rec *g_thrash;
static size_t g_thrash_n, g_thrash_cap, g_thrash_bytes;

static void thrash_reset(void)
{
    for (size_t i = 0; i < g_thrash_n; i++) {
        free(g_thrash[i].name);
        free(g_thrash[i].args);
    }
    g_thrash_n = 0;
    g_thrash_bytes = 0;
}

/* Set when a call repeated THRASH_MAX times: the turn ends on that instead of
 * looping. File scope because it is written deep in the tool loop and read
 * after it; one agent thread runs at a time, so no lock is needed. */
static int g_thrash_stop;

static int thrash_hit(const char *name, const char *args)
{
    size_t la = args ? strlen(args) : 0;
    for (size_t i = 0; i < g_thrash_n; i++) {
        if (strcmp(g_thrash[i].name, name) != 0)
            continue;
        if (strlen(g_thrash[i].args) != la)
            continue;
        if (la && memcmp(g_thrash[i].args, args, la) != 0)
            continue;
        if (++g_thrash[i].count >= THRASH_MAX)
            return 1;
        return 0;
    }
    if (g_thrash_bytes + la + strlen(name) + 1 > THRASH_BUDGET)
        return 0;
    if (g_thrash_n == g_thrash_cap) {
        g_thrash_cap = g_thrash_cap ? g_thrash_cap * 2 : 32;
        g_thrash = xrealloc(g_thrash, g_thrash_cap * sizeof *g_thrash);
    }
    g_thrash[g_thrash_n].name = xstrdup(name);
    g_thrash[g_thrash_n].args = xstrndup(args ? args : "", la);
    g_thrash[g_thrash_n].count = 1;
    g_thrash_bytes += la + strlen(name) + 1;
    g_thrash_n++;
    return 0;
}

static DWORD WINAPI para_readonly_thread(LPVOID arg)
{
    struct para_slot *s = arg;
    arena_init(&s->ta, 8 * 1024);
    struct jnode *aj = json_parse(&s->ta, s->args_json,
                                  strlen(s->args_json));
    if (aj && aj->tag != J_OBJ)
        aj = NULL;
    s->summary = aj ? args_summary(aj, s->name) : xstrdup("");
    s->output = tool_execute(s->name, aj, &s->img);
    return 0;
}

static void para_slot_free(struct para_slot *s)
{
    free(s->output);
    free(s->summary);
    free(s->img.b64);
    free(s->img.mime);
    arena_free(&s->ta);
}

/* One agent turn: stream, execute tool calls, feed results back. The
 * real cursor stays hidden for the whole turn — streaming repaints the
 * tail every frame, and a visible cursor just jumps around the output;
 * the composer paints a block caret in the draft instead. In dock mode
 * the editor re-shows the cursor when the turn ends. */

/* The finished turn's token totals: /goal accumulates them into its budget.
 * Zero when the endpoint reported no usage. */
static int64_t g_last_turn_in, g_last_turn_out;

static int agent_loop(struct config *cfg, struct conversation *cv,
                      struct session_log *slog, const char *system_prompt,
                      int auto_compact)
{
    int rc = 0;
    if (g_emit_vt)
        out_frame_puts("\x1b[?25l");
    int64_t turn_in = 0, turn_out = 0, turn_cache = 0;
    DWORD gen_ms = 0; /* time inside chat_stream, across every round */
    int turn_usage = 0, turn_has_cache = 0;
    size_t turn_req = 0, turn_shared = 0; /* last round's prefix numbers */
    int turn_prev = 0;
    size_t last_request_bytes = 0;
    int compacted_once = 0;
    g_last_turn_in = g_last_turn_out = 0;
    /* turn-level state: spinner and timer run for the whole turn (all
     * model rounds + tool executions), not per round */
    InterlockedExchange(&g_busy, 1);
    g_turn_start = GetTickCount();
    g_stream_bytes = 0;
    thrash_reset(); /* per turn: the loop restarts the clock every user turn */
    g_thrash_stop = 0;
    if (g_dock)
        status_repaint(); /* busy status right under the prompt */
    HANDLE spinner = CreateThread(NULL, 0, spinner_thread, NULL, 0, NULL);
    /* no round cap, like pi: the loop runs until the model stops calling
     * tools; Ctrl+C is the escape hatch */
    for (;;) {
        /* recycle before EVERY request, not just before every turn: a long
         * tool loop is one turn, and waiting for it to end re-pays every
         * early result for the whole loop. The two-round slack means the
         * model has already seen anything this drops. */
        if (auto_compact)
            conv_stub_tool_results(cv, NULL, TOOL_STUB_MIN,
                                   TOOL_KEEP_ROUNDS, 0);
        renderer_init(&g_renderer);
        renderer_set_width(&g_renderer);
        struct stream_state st;
        stream_state_init(&st);
        struct stream_hooks hooks = { hook_think, hook_text };

        InterlockedExchange(&g_cancel, 0);
        g_stream_bytes = 0;
        g_gen_tool[0] = '\0';
        g_gen_len = g_gen_lines = 0;
        g_tick_label[0] = '\0'; /* a cancelled round may have left progress */
        /* race safety: input that landed as the last round ended (too
         * late to interrupt) joins this request without interrupting */
        turn_feed_queue(cv, slog);
        status_repaint();
        InterlockedExchange(&g_busy, 1);
        /* request with exponential backoff: up to 3 attempts for transient
         * transport/HTTP failures, but never replay a partial stream */
        int attempt = 0;
        int status;
        DWORD t_round = GetTickCount();
        for (;;) {
            DWORD t_req = GetTickCount();
            status = chat_stream(cfg, cv, system_prompt, 1, &hooks, &st);
            gen_ms += GetTickCount() - t_req;
            last_request_bytes = st.request_bytes;
            if (status == -1)
                break; /* cancelled */
            int retryable = status == 0 || status == 408 || status == 429
                || (status >= 500 && status <= 599);
            if (!retryable)
                break;
            if (st.content.len || st.reasoning.len || st.n_calls
                || g_stream_bytes)
                break; /* a partial stream must not be replayed */
            if (++attempt >= 3)
                break;
            /* A wall-clock budget beside the attempt count: one refused
             * connect costs the OS ~2s, a blackholed one the whole connect
             * timeout, so three blind retries held a dead endpoint for a
             * minute before saying so. Fast failures still get all three
             * tries; once the round has burned its budget the error is the
             * honest answer. */
            if (GetTickCount() - t_round > 8000)
                break;
            if (g_emit_vt)
                out_printf("\r\x1b[0K\x1b[2m⚠ 连接异常，正在重试（%d/2）…\x1b[0m\r\n",
                           attempt);
            else
                out_printf("⚠ 连接异常，正在重试（%d/2）\r\n", attempt);
            for (int wait = 1000 << (attempt - 1); wait > 0; wait -= 100) {
                if (InterlockedCompareExchange(&g_cancel, 0, 0))
                    break;
                Sleep(100);
            }
            if (InterlockedCompareExchange(&g_cancel, 0, 0)) {
                status = -1;
                break;
            }
            free(st.error);
            st.error = NULL;
            st.finish = FINISH_NONE;
        }
        if (!g_stream_bytes && g_emit_vt)
            out_puts("\r\x1b[0K"); /* erase the wait spinner residue */
        renderer_end_turn(&g_renderer);

        if (st.looped) {
            /* the repeated text is dropped, not kept: holding it would
             * make every later round pay for the loop just broken */
            out_puts("⚠ 检测到输出重复循环，已中断本轮（该回复未保留）\r\n");
            stream_state_free(&st);
            rc = 1;
            break;
        }
        if (status == -1) {
            if (InterlockedCompareExchange(&g_steer, 0, 0)) {
                /* enter steer: the new text becomes the user turn
                 * the model answers right now */
                InterlockedExchange(&g_steer, 0);
                /* keep what it already said. Those tokens are spent, the
                 * text is already on screen, and dropping it makes the model
                 * write the same paragraph again on the next round. */
                turn_commit_text(cv, slog, &st);
                stream_state_free(&st);
                turn_feed_queue(cv, slog);
                continue;
            }
            out_puts("^C 已中断\r\n");
            stream_state_free(&st);
            rc = 130;
            break;
        }
        if (st.error) {
            /* a context-overflow rejection arrives before any byte
             * streams, so folding the history and replaying the request
             * is safe — the loop heals instead of dying. If nothing can
             * be folded (overflow is all in the current tail) fall
             * through to the honest error. */
            if (!compacted_once && !st.content.len && !st.reasoning.len
                && error_is_context_overflow(st.error)) {
                out_puts("⚠ 上下文超限，尝试压缩后重试\r\n");
                /* the rejection usually states the real ceiling; if it does
                 * not, back off by half and let the next attempt measure */
                int64_t real = parse_context_limit(st.error);
                int64_t was = compact_window_tokens();
                if (!adopt_window_tokens(real))
                    adopt_window_tokens(was / 2);
                if (compact_window_tokens() != was)
                    out_printf("  窗口改用 %lld token\r\n",
                               (long long)compact_window_tokens());
                int recovered = conv_compact(cfg, cv, slog);
                if (!recovered)
                    recovered = conv_stub_tool_results(cv, NULL, 0, 0, 1);
                if (recovered) {
                    compacted_once = 1;
                    stream_state_free(&st);
                    continue;
                }
            }
            /* ki's error row: red X, dim source tag, plain message */
            if (g_emit_vt)
                out_printf("\x1b[31mX\x1b[0m \x1b[2msystem:\x1b[0m %s\r\n",
                           st.error);
            else
                out_printf("X system: %s\r\n", st.error);
            stream_state_free(&st);
            rc = 1;
            break;
        }
        /* A 200 whose stream ended with no finish_reason, no usage chunk and
         * no [DONE] was closed by the peer mid-answer. The transport cannot
         * see it — WinHTTP reports a clean EOF either way — so the reply would
         * sit there stopping mid-word with nothing said, which reads as a
         * rendering bug. Say it, and leave the fact in the message the model
         * reads next round: display == model view for truncation too, and
         * "继续" then continues instead of guessing. */
        if (status == 200 && st.finish == FINISH_NONE && !st.got_usage
            && (st.content.len || st.reasoning.len || st.n_calls)) {
            out_puts("⚠ 回复在传输中被提前关闭，内容不完整\r\n");
            if (st.content.len)
                buf_appends(&st.content,
                            "\n\n[传输中断：此回复未完整接收]");
        }
        if (st.got_usage) {
            /* accumulate: the usage line prints once per user turn */
            turn_in += st.prompt_tokens;
            turn_out += st.completion_tokens;
            turn_usage = 1;
            g_ctx_tokens = st.prompt_tokens; /* for the status line */
            if (st.has_cache) {
                turn_cache += st.cache_tokens;
                turn_has_cache = 1;
            }
            /* the prefix numbers describe the LAST round only: that is the
             * one whose cache state the next round inherits */
            turn_req = st.request_bytes;
            turn_shared = st.request_shared;
            turn_prev = st.request_prev;
            session_log_usage(slog, st.prompt_tokens, st.completion_tokens,
                              st.cache_tokens, st.has_cache,
                              st.request_bytes, st.request_shared,
                              st.request_prev);
        }
        if (st.finish != FINISH_TOOL_CALLS || st.n_calls == 0) {
            /* no tool will run, so nothing will clear the generation
             * progress the way the tool loop does below */
            g_tick_label[0] = '\0';
            turn_commit_text(cv, slog, &st);
            if (st.finish == FINISH_LENGTH) {
                /* the model hit its output cap mid-answer: the human must
                 * see that the reply is incomplete — display == model view
                 * for truncation too */
                out_puts("⚠ 回复在模型输出上限处被截断\r\n");
            }
            stream_state_free(&st);
            if (queue_pending()) {
                /* input landed during the final stream (too late to
                 * interrupt): the turn continues with it */
                turn_feed_queue(cv, slog);
                continue;
            }
            break;
        }
        struct message *m = conv_add_take(cv, "assistant",
                                          st.content.len
                                              ? buf_detach(&st.content)
                                              : NULL);
        m->n_calls = st.n_calls;
        m->calls = xcalloc(st.n_calls, sizeof *m->calls);
        for (size_t i = 0; i < st.n_calls; i++) {
            m->calls[i].id = xstr_or(st.calls[i].id, "");
            m->calls[i].name = xstr_or(st.calls[i].name, "unknown");
            /* take the streamed args buffer whole instead of copying what
             * can be a 100KB write payload just to free the original */
            m->calls[i].args = st.calls[i].args.p
                                   ? buf_detach(&st.calls[i].args)
                                   : xstrdup("{}");
        }
        session_log_message(slog, m);
        /* The records live in their own block, m does not: every tool
         * message appended below can realloc cv->msgs and move m, so the
         * loop reads the calls through this snapshot. */
        struct tool_call_rec *calls = m->calls;
        size_t n_calls = m->n_calls;

        /* a tools-only response fires no text hooks, so g_busy still reads 1
         * (waiting): the spinner must go quiet before the tool lines print,
         * or it stamps over them */
        InterlockedExchange(&g_busy, 2);
        /* A read-only call repeated verbatim inside one batch is work already
         * paid for: it runs nothing and answers with a stub pointing at the
         * result the model can read in this same conversation. That saves the
         * I/O and — more to the point — keeps one copy of the text instead of
         * two, where every later round would re-send both. */
        int *dup = xcalloc(n_calls, sizeof *dup);
        for (size_t i = 0; i < n_calls; i++) {
            if (!tool_readonly(calls[i].name))
                continue;
            size_t la = calls[i].args ? strlen(calls[i].args) : 0;
            for (size_t j = 0; j < i && !dup[i]; j++) {
                if (dup[j] || !tool_readonly(calls[j].name)
                    || strcmp(calls[i].name, calls[j].name) != 0)
                    continue;
                size_t lb = calls[j].args ? strlen(calls[j].args) : 0;
                if (lb == la && (!la || memcmp(calls[i].args, calls[j].args,
                                               la) == 0))
                    dup[i] = 1;
            }
        }
        /* Leading read-only calls run in parallel: the model emits them in one
         * batch precisely because they are independent, and each is a pure
         * I/O wait. Only the leading run qualifies — a read sitting behind a
         * write in the same batch may be meant to see that write's result.
         * Results still join, display and log in call order: display ==
         * model view. */
        size_t n_para = 0;
        while (n_para < n_calls && tool_readonly(calls[n_para].name)
               && !dup[n_para])
            n_para++;
        if (n_para < 2)
            n_para = 0; /* one call gains nothing from a thread, and every
                         * `i < n_para` below indexes the slot array that only
                         * the >=2 branch allocates */
        struct para_slot *para = NULL;
        if (n_para >= 2) {
            para = xcalloc(n_para, sizeof *para);
            for (size_t k = 0; k < n_para; k++) {
                para[k].name = calls[k].name;
                para[k].args_json = calls[k].args;
                para[k].th = CreateThread(NULL, 0, para_readonly_thread,
                                          &para[k], 0, NULL);
                if (!para[k].th) {
                    /* thread starvation: drain what did start and fall back
                     * to the serial path — reads are pure, re-running them
                     * is harmless */
                    for (size_t j = 0; j < n_para; j++) {
                        if (para[j].th) {
                            WaitForSingleObject(para[j].th, INFINITE);
                            CloseHandle(para[j].th);
                        }
                        para_slot_free(&para[j]);
                    }
                    free(para);
                    para = NULL;
                    n_para = 0;
                    break;
                }
            }
            /* one label for the whole parallel burst: naming a single tool
             * while N run would be a lie, and silence would read as a hang.
             * Distinct tool names, in first-appearance order. */
            if (para) {
                char kinds[64] = { 0 };
                size_t kn = 0;
                for (size_t k = 0; k < n_para && kn + 8 < sizeof kinds; k++) {
                    if (strstr(kinds, calls[k].name))
                        continue;
                    kn += (size_t)snprintf(kinds + kn, sizeof kinds - kn,
                                           "%s%s", kn ? "+" : "",
                                           calls[k].name);
                }
                AcquireSRWLockExclusive(&g_out_lock);
                snprintf(g_tick_label, sizeof g_tick_label, "并行 %s ×%zu",
                         kinds, n_para);
                g_tick_start = GetTickCount();
                ReleaseSRWLockExclusive(&g_out_lock);
            }
        }
        /* execute every call: full display, full output to the model */
        int cancelled = 0;
        for (size_t i = 0; i < n_calls; i++) {
            const char *name = calls[i].name;

            char *output;
            struct tool_img img = { NULL, NULL };
            char *summary;
            if (dup[i]) {
                /* nothing ran, so the call line is all there is to show */
                summary = xstrdup("");
                output = xstrdup("[identical to an earlier call in this batch "
                                 "— its result is already in this conversation]");
                tool_show_call(name, summary);
            } else if (i < n_para) {
                /* reap the parallel read in call order: every thread was
                 * launched above, so this is a join, not a fresh start */
                WaitForSingleObject(para[i].th, INFINITE);
                CloseHandle(para[i].th);
                para[i].th = NULL;
                summary = para[i].summary;
                tool_show_call(name, summary);
                output = para[i].output;
                img = para[i].img;
                arena_free(&para[i].ta); /* the output is heap, not arena */
            } else {
                struct arena ta;
                arena_init(&ta, 8 * 1024);
                struct jnode *aj = json_parse(&ta, calls[i].args,
                                              strlen(calls[i].args));
                if (aj && aj->tag != J_OBJ)
                    aj = NULL;
                summary = aj ? args_summary(aj, name) : xstrdup("");
                tool_show_call(name, summary);

                /* the status line carries the running tool's name and args */
                AcquireSRWLockExclusive(&g_out_lock);
                snprintf(g_tick_label, sizeof g_tick_label, "%s · %s", name,
                         summary);
                g_tick_start = GetTickCount();
                ReleaseSRWLockExclusive(&g_out_lock);
                /* the args are already parsed: executing on the same node
                 * skips a second full JSON pass (a write's content alone can
                 * be 100KB); the arena owns aj and must outlive the call */
                output = tool_execute(name, aj, &img);
                arena_free(&ta);
            }
            /* the burst label survives every reap: only the last one (or a
             * serial tool finishing) clears it */
            if (i >= n_para || i + 1 == n_para) {
                AcquireSRWLockExclusive(&g_out_lock);
                g_tick_label[0] = '\0';
                ReleaseSRWLockExclusive(&g_out_lock);
            }
            free(summary);
            const struct tool_spec *ts = tool_lookup(name);
            if (ts && ts->quiet_ok) {
                /* file content goes to the model only, but read FAILURES
                 * must be visible — display == model view for errors too */
                if (output && strncmp(output, "error:", 6) == 0)
                    tool_show_exit(output);
            } else {
                tool_show_exit(output);
                tool_show_output(output);
            }
            status_repaint(); /* refresh the status row after tool output */

            struct message *tm = conv_add_take(cv, "tool", output);
            tm->tool_call_id = xstrdup(calls[i].id);
            if (img.b64 && img.mime) {
                struct image_part part = { img.mime, img.b64 };
                DA_PUSH(tm->images, part); /* ownership moves */
            } else {
                free(img.b64);
                free(img.mime);
            }
            session_log_message(slog, tm);
            /* Degenerate tool thrash: this exact call, three times in one turn.
             * content_looping catches a model stuck repeating its own words;
             * nothing catches it stuck repeating its own tool calls (read the
             * region, edit, read it back, edit again) — and an ordinary turn
             * has neither a round cap nor a token cap, only /goal does. */
            if (!dup[i] && thrash_hit(name, calls[i].args)) {
                out_printf("⚠ 检测到工具调用重复循环（%s ×%d），已中止本轮\r\n",
                           name, THRASH_MAX);
                for (size_t j = i + 1; j < n_para; j++) {
                    if (para[j].th) {
                        WaitForSingleObject(para[j].th, INFINITE);
                        CloseHandle(para[j].th);
                        para[j].th = NULL;
                    }
                    para_slot_free(&para[j]);
                }
                turn_stub_rest(cv, slog, calls, i + 1, n_calls,
                               "(not run: this call repeated too many times in "
                               "one turn)");
                g_thrash_stop = 1;
                break;
            }
            if (InterlockedCompareExchange(&g_cancel, 0, 0)) {
                cancelled = 1;
                /* the assistant message holding all N tool_calls is already
                 * committed and logged: every call left unrun needs a tool
                 * message, or the next request is a 400 that --continue
                 * replays for the rest of the session. Parallel reads that
                 * already started are drained and discarded — the stub is
                 * what the model sees for them. */
                for (size_t j = i + 1; j < n_para; j++) {
                    if (para[j].th) {
                        WaitForSingleObject(para[j].th, INFINITE);
                        CloseHandle(para[j].th);
                        para[j].th = NULL;
                    }
                    para_slot_free(&para[j]);
                }
                turn_stub_rest(cv, slog, calls, i + 1, n_calls,
                               "(cancelled before this call ran)");
                break;
            }
        }
        free(dup);
        free(para);
        stream_state_free(&st);
        if (g_thrash_stop) {
            rc = 1;
            break;
        }
        if (cancelled) {
            if (InterlockedCompareExchange(&g_steer, 0, 0)) {
                /* enter steer out of a tool run: the new text drives
                 * the next round instead of ending the turn */
                InterlockedExchange(&g_steer, 0);
                turn_feed_queue(cv, slog);
                continue;
            }
            out_puts("^C 已取消\r\n");
            rc = 130;
            break;
        }
    }
    thrash_reset();
    if (turn_usage) {
        /* /goal's budget accounting reads these after the turn returns */
        g_last_turn_in = turn_in;
        g_last_turn_out = turn_out;
        /* once per user turn: in/out token counts, prompt cache hit rate
         * and total wall time, then a blank row for the next composer */
        char fs[16];
        fmt_secs(fs, sizeof fs, (GetTickCount() - g_turn_start) / 1000);
        /* Rate over stream time only: wall time includes the tool runs
         * between rounds, which would make a build-heavy turn read ~1 t/s */
        char tps[20];
        tps[0] = '\0';
        if (gen_ms && turn_out > 0) {
            int64_t t10 = (turn_out * 10000) / (int64_t)gen_ms;
            snprintf(tps, sizeof tps, " · %lld.%d t/s", (long long)(t10 / 10),
                     (int)(t10 % 10));
        }
        /* percent to one decimal: 1-2% hits are common on short turns and
         * rounding them to 0% reads as "caching is broken" */
        int64_t ch10 = turn_in > 0 ? turn_cache * 1000 / turn_in : 0;
        /* sh: how much of the last request repeated the previous one from
         * byte 0. High sh with ch 0 points at the endpoint; a falling sh
         * points at us (something in the prefix moved). */
        char shp[32];
        shp[0] = '\0';
        if (turn_prev && turn_req > 0) {
            int64_t sh10 = (int64_t)(turn_shared * 1000 / turn_req);
            snprintf(shp, sizeof shp, " · sh %lld.%d%%",
                     (long long)(sh10 / 10), (int)(sh10 % 10));
        }
        if (g_emit_vt)
            out_puts("\x1b[2m");
        if (turn_has_cache && turn_in > 0)
            out_printf("[in %lld · out %lld%s · ch %lld.%d%%%s · %s]\r\n",
                       (long long)turn_in, (long long)turn_out, tps,
                       (long long)(ch10 / 10), (int)(ch10 % 10), shp, fs);
        else
            out_printf("[in %lld · out %lld%s%s · %s]\r\n", (long long)turn_in,
                       (long long)turn_out, tps, shp, fs);
        if (g_emit_vt)
            out_puts("\x1b[0m");
        out_puts("\r\n");
    }
    /* auto-compact between user turns: once the request outgrows 3/4 of
     * the context window, fold the old history into a summary so the next
     * turn starts light. Endpoints that omit usage are covered by a rough
     * request-size estimate (~1 token per 2 bytes, CJK-heavy). -p mode
     * never compacts (nothing follows). */
    /* the last round's prompt size IS the current context. turn_in sums
     * every round of this turn, so a four-round tool loop would trip this
     * at a quarter of the real usage and fold away live history. */
    int64_t prompt_now = turn_usage ? g_ctx_tokens
                                    : (int64_t)(last_request_bytes / 2);
    /* Tool output is the bulk of what every later round re-pays, and the
     * one thing the model can always fetch back with a tool call. Take it
     * back first: it costs no request, so a turn that would have needed a
     * summarizer round may not need one at all. */
    if (rc == 0 && auto_compact && prompt_now >= compact_window_tokens() / 4) {
        size_t freed = 0;
        if (conv_stub_tool_results(cv, &freed, 0, 0, 1)) {
            int64_t est = (int64_t)(freed / 2); /* ~1 token per 2 bytes */
            prompt_now = est < prompt_now ? prompt_now - est : 0;
        }
    }
    if (rc == 0 && auto_compact && prompt_now >= compact_window_tokens() / 4 * 3)
        conv_compact(cfg, cv, slog);
    InterlockedExchange(&g_busy, 0);
    if (spinner) {
        /* End the spinner's frame nap rather than waiting it out: the join
         * cost up to ~33 ms of dead air between the answer ending and the
         * composer taking input again. If it already exited, the auto-reset
         * event stays armed and only buys the next turn one early frame. */
        if (!g_spinner_wake)
            g_spinner_wake = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (g_spinner_wake)
            SetEvent(g_spinner_wake);
        WaitForSingleObject(spinner, 3000);
        CloseHandle(spinner);
    }
    InterlockedExchange(&g_steer, 0); /* a steer aimed at an already-dead run */
    status_repaint(); /* the model name returns to the status row */
    session_flush(slog); /* the turn's records land in one write */
    if (!g_dock && g_emit_vt)
        out_puts("\x1b[?25h"); /* dock mode: the editor re-shows it */
    return rc;
}

/* --- /goal: bounded autonomous mode --------------------------------------
 * One large task delivered without the user re-typing "继续" between rounds.
 * Nothing new is built here: every round IS a full agent_loop (stream,
 * tools, display, session log, auto-compaction), so a goal run behaves
 * exactly like one long turn — it just continues itself with a tagged nudge
 * instead of waiting for keystrokes. Three hard stops, any of which ends it:
 * the model prefixes its final answer with ✅ (the protocol it was given),
 * a budget (rounds / wall-clock / tokens, env-tunable), or the human — a
 * Ctrl+C round or any real user message hands control straight back. */
#define GOAL_DONE_MARK "\xE2\x9C\x85"                          /* ✅ */
#define GOAL_TAG       "\xE7\x9B\xAE\xE6\xA0\x87\xE6\xA8\xA1\xE5\xBC\x8F" /* 目标模式 */


static int goal_loop(struct config *cfg, struct conversation *cv,
                     struct session_log *slog, const char *system_prompt,
                     const char *task)
{
    /* Budgets are env-tunable; a goal is a large task by definition, so the
     * defaults are generous and a missing or absurd value falls back. */
    int64_t max_rounds = env_i64("KK_GOAL_ROUNDS", 1, 50);
    int64_t max_minutes = env_i64("KK_GOAL_MINUTES", 1, 60);
    int64_t max_tokens = env_i64("KK_GOAL_TOKENS", 1, 5000000);
    DWORD t0 = GetTickCount();
    int64_t spent = 0;

    /* the goal and its protocol ride in the first user message: the model
     * must know it is autonomous, how to finish, and that it has a budget */
    struct buf first = BUF_INIT;
    buf_appendf(&first,
                GOAL_TAG "·自主任务：%s\n"
                "规则：自主连续推进，不要向用户提问或等待确认；每轮尽量批量"
                "并行调用工具，减少往返；全部完成时，最终回复的第一行以 ✅ "
                "开头并附简要总结；尚未完成就继续工作。",
                task);
    struct message *um = conv_add_take(cv, "user", buf_detach(&first));
    attach_user_images(um, task);
    session_log_message(slog, um);

    char tok[24];
    if (max_tokens >= 1000000)
        snprintf(tok, sizeof tok, "%.1fM", (double)max_tokens / 1e6);
    else
        snprintf(tok, sizeof tok, "%lld", (long long)max_tokens);
    out_printf(vt_or("\x1b[36m🎯 目标模式\x1b[0m \x1b[2m预算 %lld 轮 / %lld "
                     "分钟 / %s tokens · Ctrl+C 随时中止\x1b[0m\r\n",
                     "🎯 目标模式 预算 %lld 轮 / %lld 分钟 / %s tokens"
                     " · Ctrl+C 随时中止\r\n"),
               (long long)max_rounds, (long long)max_minutes, tok);

    for (int64_t round = 1;; round++) {
        int rc = agent_loop(cfg, cv, slog, system_prompt, 1);
        spent += g_last_turn_in + g_last_turn_out;
        if (rc != 0) {
            /* Ctrl+C (130) or a failed round: the human is back in control */
            out_puts("🎯 目标模式已停止\r\n");
            return rc;
        }
        size_t ai = conv_rfind(cv, "assistant");
        if (ai != cv->msgs.n && cv->msgs.p[ai].content
            && strncmp(cv->msgs.p[ai].content, GOAL_DONE_MARK,
                       sizeof GOAL_DONE_MARK - 1) == 0) {
            out_printf(vt_or("\x1b[2m🎯 目标完成：%lld 轮 · in+out %lld "
                             "tokens\x1b[0m\r\n",
                             "🎯 目标完成：%lld 轮 · in+out %lld tokens\r\n"),
                       (long long)round, (long long)spent);
            return 0;
        }
        /* a real user message (a steer, queued input) is untagged: a goal
         * run never overrules the human — hand control back */
        size_t ui = conv_rfind(cv, "user");
        if (ui != cv->msgs.n && cv->msgs.p[ui].content
            && strncmp(cv->msgs.p[ui].content, GOAL_TAG,
                       sizeof GOAL_TAG - 1) != 0) {
            out_puts("🎯 检测到你的输入，目标模式交还控制权\r\n");
            return 0;
        }
        if (round >= max_rounds
            || (GetTickCount() - t0) / 60000 >= (DWORD)max_minutes
            || spent >= max_tokens) {
            out_printf(vt_or("\x1b[2m🎯 预算用尽，目标模式停止（已完成 %lld "
                             "轮 · in+out %lld tokens）\x1b[0m\r\n",
                             "🎯 预算用尽，目标模式停止（已完成 %lld 轮 · "
                             "in+out %lld tokens）\r\n"),
                       (long long)round, (long long)spent);
            return 0;
        }
        out_printf(vt_or("\x1b[2m🎯 第 %lld/%lld 轮 · 累计 in+out %lld "
                         "tokens\x1b[0m\r\n",
                         "🎯 第 %lld/%lld 轮 · 累计 in+out %lld tokens\r\n"),
                   (long long)round, (long long)max_rounds,
                   (long long)spent);
        /* the nudge is the user turn the next round answers — tagged, so
         * the "human spoke" check above can tell it apart from real input.
         * The remaining budget rides along: a model that knows the clock is
         * near can prioritize instead of spending the last round on setup. */
        struct buf nudge = BUF_INIT;
        buf_appendf(&nudge,
                    GOAL_TAG "·第 %lld 轮：继续推进上面的任务，尚未完成就"
                    "不要停；全部完成时以 ✅ 开头收尾。（剩余约 %lld 轮 / "
                    "%lld 分钟）",
                    (long long)(round + 1),
                    (long long)(max_rounds - round),
                    (long long)(max_minutes
                                - (GetTickCount() - t0) / 60000));
        struct message *nm = conv_add_take(cv, "user", buf_detach(&nudge));
        session_log_message(slog, nm);
        user_line_show(nm->content, strlen(nm->content));
    }
}

static const char KK_HELP[] =
    "kk " KK_VERSION " — 单文件流式编程代理（Windows）\r\n"
    "usage: kk [flags] [prompt]\r\n"
    "  -p, --prompt TEXT   一次性模式：流式输出一个回答后退出\r\n"
    "  -c, --continue      继续最近一次会话\r\n"
    "  --base URL          API 地址（环境变量 KK_BASE_URL）\r\n"
    "  --key KEY           API 密钥（环境变量 KK_API_KEY）\r\n"
    "  --model MODEL       模型 id（环境变量 KK_MODEL）\r\n"
    "  --version           打印版本\r\n"
    "  -h, --help          打印本帮助\r\n"
    "不带参数启动交互式 REPL。\r\n"
    "环境变量（也可用 %APPDATA%\\kk\\config 写前三项）：\r\n"
    "  KK_BASE_URL / KK_API_KEY / KK_MODEL  连接与模型\r\n"
    "  KK_MAX_OUTPUT_TOKENS 单次输出上限（默认 32768）；KK_CONTEXT_WINDOW\r\n"
    "    假定的上下文窗口（默认 262144）；KK_READ_MAX_BYTES read 单页上限\r\n"
    "    （默认 65536）\r\n"
    "  KK_IMG_MAX_EDGE 贴图长边像素上限（默认 1568，<64 关闭）；\r\n"
    "    KK_IMG_MAX_BYTES 贴图 base64 后上限（默认 8MB）\r\n"
    "  KK_DUMP_REQ=<路径> 把每次发出的请求体覆盖写到该文件（查「这轮为什么\r\n"
    "    比日志里的消息大」）；KK_FORCE_CONSOLE 重定向下仍按 VT 输出（测试用）\r\n";

static void config_print_missing(const struct config *cfg)
{
    if (!cfg->api_key || !*cfg->api_key)
        fatal("未设置 API 密钥：设置 KK_API_KEY（或 OPENAI_API_KEY）、"
              "`kk --key KEY`，或 %s\\config", g_appdata_dir);
    if (!cfg->model || !*cfg->model)
        fatal("未设置模型：设置 KK_MODEL、`kk --model M`，或 %s\\config",
              g_appdata_dir);
}

static int run_prompt(struct config *cfg, const char *prompt, int cont)
{
    config_print_missing(cfg);

    struct conversation cv;
    conv_init(&cv);
    struct session_log slog;
    session_open(&slog, cont, &cv);

    if (prompt) {
        struct message *um = conv_add(&cv, "user", prompt);
        attach_user_images(um, prompt);
        session_log_message(&slog, um);
    } else if (cv.msgs.n == 0) {
        out_puts("会话为空，没有可继续的内容\r\n");
        session_close(&slog);
        conv_free(&cv);
        return 0;
    }

    /* one-shot mode sees the same system prompt as the REPL: the AGENTS.md
     * hierarchy applies to every request, not just interactive ones. No head
     * report: -p's stdout is the answer, not a status surface. */
    char *sysp = system_prompt_build(0);

    int rc = agent_loop(cfg, &cv, &slog, sysp, 0);

    free(sysp);
    session_close(&slog);
    conv_free(&cv);
    return rc;
}

/* --- crash diagnostics: a text scene of the fault ------------------------ */
/* A crash must leave something behind. MiniDumpWriteDump cannot do it on this
 * machine (measured with a standalone probe: ERROR_INVALID_PARAMETER for
 * every argument variant, and the same failure from a healthy process), so
 * this writes the exception code, the address touched, the faulting
 * instruction and the return addresses as RVAs, which kk.map names offline.
 * Static buffers and one WriteFile each: the allocator may be what died, and
 * a handler runs on whatever stack is left. */
static LONG WINAPI kk_crash_filter(EXCEPTION_POINTERS *ep)
{
    static char rec[512];
    static void *frames[16];
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
    size_t img = 0;
    if (base) { /* our own headers are mapped and readable */
        const IMAGE_DOS_HEADER *dh = (const IMAGE_DOS_HEADER *)base;
        const IMAGE_NT_HEADERS *nt =
            (const IMAGE_NT_HEADERS *)(base + (ptrdiff_t)dh->e_lfanew);
        img = (size_t)nt->OptionalHeader.SizeOfImage;
    }
    ULONG n = RtlCaptureStackBackTrace(0, 16, frames, NULL);
    int len = snprintf(rec, sizeof rec,
                       "kk crash code=0x%08lX rip=+%llX fault=%llX\n",
                       (unsigned long)er->ExceptionCode,
                       (unsigned long long)((uintptr_t)er->ExceptionAddress -
                                            base),
                       er->NumberParameters > 1
                           ? (unsigned long long)er->ExceptionInformation[1]
                           : 0ULL);
    for (ULONG i = 0; i < n && len < (int)sizeof rec - 24; i++) {
        uintptr_t a = (uintptr_t)frames[i];
        if (a >= base && a - base < img)
            len += snprintf(rec + len, sizeof rec - len, " +%llX",
                            (unsigned long long)(a - base));
        else
            len += snprintf(rec + len, sizeof rec - len, " sys%llX",
                            (unsigned long long)a);
    }
    snprintf(rec + len, sizeof rec - len, "\n");
    DWORD wr = 0;
    HANDLE f = CreateFileA("kk_crash.txt", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        WriteFile(f, rec, (DWORD)strlen(rec), &wr, NULL);
        CloseHandle(f);
    }
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), rec, (DWORD)strlen(rec),
              &(DWORD){0}, NULL);
    return EXCEPTION_EXECUTE_HANDLER;
}

/* A malformed command line. The prewarm shell inherited our stdio pipes, so it
 * has to die before the process returns or a reader waits forever for EOF. */
static int flag_error(const char *flag, const char *why)
{
    fprintf(stderr, "kk: %s %s（见 --help）\n", flag, why);
    ps_kill();
    return 2;
}

int wmain(int argc, wchar_t **wargv)
{
    SetUnhandledExceptionFilter(kk_crash_filter);
    term_init();
    dirs_init();

    /* pre-index the workspace while the user is still typing; a no-op thread
     * when fff.dll is absent. The shell session warms in the background too:
     * a synchronous spawn held every startup hostage to ~1.1s of PowerShell
     * cold start */
    HANDLE warm[2];
    warm[0] = CreateThread(NULL, 0, fff_warmup, NULL, 0, NULL);
    warm[1] = CreateThread(NULL, 0, ps_prewarm, NULL, 0, NULL);
    for (int i = 0; i < 2; i++)
        if (warm[i])
            CloseHandle(warm[i]);

    /* CRT argv decodes the ANSI codepage; take the wide command line and
     * convert to UTF-8 so every byte after this point is UTF-8. */
    char **argv = xmalloc((size_t)argc * sizeof *argv);
    for (int i = 0; i < argc; i++) {
        argv[i] = utf8_from_w(wargv[i]);
        if (!argv[i])
            argv[i] = xstrdup("");
    }

    struct config cfg;
    config_load(&cfg);

    const char *prompt = NULL;
    int cont = 0;
    for (int i = 1; i < argc; i++) {
        char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            out_puts(KK_HELP);
            ps_kill(); /* the prewarm shell inherited our stdio pipes:
                        * it must die before exit or a reader waits
                        * forever for EOF */
            return 0;
        } else if (strcmp(a, "--version") == 0) {
            out_printf("kk " KK_VERSION "\r\n");
            ps_kill();
            return 0;
        } else if (strcmp(a, "--base") == 0 || strcmp(a, "--key") == 0
                   || strcmp(a, "--model") == 0) {
            if (i + 1 >= argc)
                return flag_error(a, "缺少取值");
            char **slot = strcmp(a, "--base") == 0 ? &cfg.base_url
                          : strcmp(a, "--key") == 0 ? &cfg.api_key
                                                    : &cfg.model;
            free(*slot);
            *slot = xstrdup(argv[++i]);
        } else if (strcmp(a, "-c") == 0 || strcmp(a, "--continue") == 0) {
            cont = 1;
        } else if (strcmp(a, "-p") == 0 || strcmp(a, "--prompt") == 0) {
            /* a missing value is an error, never a silent skip: `kk -p` used
             * to fall through to the REPL as if the flag had not been typed */
            if (i + 1 >= argc)
                return flag_error(a, "缺少取值");
            prompt = argv[++i];
        } else if (a[0] == '-') {
            return flag_error(a, "未知参数");
        } else {
            prompt = a;
        }
    }

    if (!prompt && !cont) {
        int rc = run_repl(&cfg);
        config_free(&cfg);
        ps_kill();
        return rc;
    }

    int rc = run_prompt(&cfg, prompt, cont);
    config_free(&cfg);
    ps_kill();
    return rc;
}
