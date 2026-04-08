/*
 * cjson_driver.c — thin CLI wrapper around cJSON for fuzzer integration.
 *
 * Supports two input modes so the same binary works for both your fuzzer
 * and AFL++ / NEUZZ:
 *
 *   Mode 1 — inline (your fuzzer):
 *     ./cjson_driver --ipstr=<json_string>
 *
 *   Mode 2 — file (AFL++ / NEUZZ via @@):
 *     ./cjson_driver <filepath>
 *     afl-fuzz -Q ... -- ./cjson_driver @@
 *
 *   Mode 3 — stdin (AFL++ without @@):
 *     echo '{}' | ./cjson_driver
 *
 * Exit codes:
 *   0  — parsed successfully (PASS)
 *   1  — parse error reported via stdout (invalidity)
 *   2+ — unexpected crash (CRASH)
 *
 * Build (plain, shared binary for all fuzzers under QEMU):
 *   gcc cjson_driver.c cJSON.c -o cjson_driver -I. -lm
 *
 * Build (ASAN, for crash triage after bugs found):
 *   gcc cjson_driver.c cJSON.c -o cjson_driver_asan -I. -lm -fsanitize=address,undefined
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

#define PREFIX     "--ipstr="
#define PREFIX_LEN 8
#define MAX_INPUT  65536

static void run_parse(const char *input) {
    cJSON *parsed = cJSON_Parse(input);

    if (!parsed) {
        const char *err = cJSON_GetErrorPtr();
        if (err) {
            printf("An invalidity bug has been triggered: parse error near '%.*s'\n",
                   32, err);
        } else {
            printf("An invalidity bug has been triggered: unknown parse error\n");
        }
        fflush(stdout);
        exit(1);
    }

    int type = parsed->type & 0xFF;
    const char *type_name = "unknown";
    switch (type) {
        case cJSON_False:  type_name = "false";  break;
        case cJSON_True:   type_name = "true";   break;
        case cJSON_NULL:   type_name = "null";   break;
        case cJSON_Number: type_name = "number"; break;
        case cJSON_String: type_name = "string"; break;
        case cJSON_Array:  type_name = "array";  break;
        case cJSON_Object: type_name = "object"; break;
    }
    printf("Parsed successfully: type=%s\n", type_name);
    fflush(stdout);

    cJSON_Delete(parsed);
    exit(0);
}

int main(int argc, char *argv[]) {
    /* Mode 1: --ipstr=<content> (your fuzzer) */
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], PREFIX, PREFIX_LEN) == 0) {
            run_parse(argv[i] + PREFIX_LEN);
        }
    }

    /* Mode 2: positional file path argument (AFL++ @@ substitution) */
    if (argc == 2 && argv[1][0] != '-') {
        FILE *f = fopen(argv[1], "rb");
        if (!f) {
            fprintf(stderr, "Cannot open file: %s\n", argv[1]);
            return 1;
        }
        char *buf = malloc(MAX_INPUT + 1);
        if (!buf) return 1;
        size_t n = fread(buf, 1, MAX_INPUT, f);
        fclose(f);
        buf[n] = '\0';
        run_parse(buf);
        free(buf);
    }

    /* Mode 3: stdin (AFL++ without @@, or piped input) */
    char *buf = malloc(MAX_INPUT + 1);
    if (!buf) return 1;
    size_t n = fread(buf, 1, MAX_INPUT, stdin);
    buf[n] = '\0';
    run_parse(buf);
    free(buf);
}
