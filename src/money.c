#include "money.h"

#include <ctype.h>
#include <stddef.h>

bool money_parse_yuan(const char *text, int64_t minimum_cents,
                      int64_t maximum_cents, int64_t *cents) {
    if (!text || !*text || !cents || minimum_cents < 0 ||
        maximum_cents < minimum_cents) return false;

    int64_t whole = 0;
    int64_t maximum_whole = maximum_cents / 100;
    const char *p = text;
    if (!isdigit((unsigned char)*p)) return false;
    do {
        int digit = *p++ - '0';
        if (whole > maximum_whole / 10 ||
            (whole == maximum_whole / 10 && digit > maximum_whole % 10))
            return false;
        whole = whole * 10 + digit;
    } while (isdigit((unsigned char)*p));

    int fraction = 0;
    if (*p == '.') {
        ++p;
        if (!isdigit((unsigned char)*p)) return false;
        fraction = (*p++ - '0') * 10;
        if (isdigit((unsigned char)*p)) {
            fraction += *p++ - '0';
            if (isdigit((unsigned char)*p)) return false;
        }
    }
    if (*p) return false;
    if (whole > (maximum_cents - fraction) / 100) return false;

    int64_t result = whole * 100 + fraction;
    if (result < minimum_cents || result > maximum_cents) return false;
    *cents = result;
    return true;
}

bool money_parse_json_integer(const char *text, int64_t *value) {
    if (!text || !value) return false;
    while (isspace((unsigned char)*text)) ++text;
    bool negative = *text == '-';
    if (negative) ++text;
    if (!isdigit((unsigned char)*text)) return false;
    if (*text == '0' && isdigit((unsigned char)text[1])) return false;

    uint64_t limit = negative ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX;
    uint64_t magnitude = 0;
    do {
        unsigned int digit = (unsigned int)(*text++ - '0');
        if (magnitude > (limit - digit) / 10) return false;
        magnitude = magnitude * 10 + digit;
    } while (isdigit((unsigned char)*text));
    while (isspace((unsigned char)*text)) ++text;
    if (*text != ',' && *text != '}' && *text != 0) return false;

    if (negative && magnitude == (uint64_t)INT64_MAX + 1) {
        *value = INT64_MIN;
    } else {
        *value = negative ? -(int64_t)magnitude : (int64_t)magnitude;
    }
    return true;
}
