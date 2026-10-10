#include "../src/money.h"

#include <stdio.h>
#include <string.h>

static int check(int condition, const char *name) {
    if (condition) return 1;
    fprintf(stderr, "FAIL: %s\n", name);
    return 0;
}

int main(void) {
    int ok = 1;
    int64_t cents = -1;
    ok &= check(money_parse_yuan("1.00", 1, 1000000000, &cents) && cents == 100,
                "parse one yuan exactly");
    ok &= check(money_parse_yuan("0.10", 1, 1000000000, &cents) && cents == 10,
                "parse ten fen exactly");
    ok &= check(money_parse_yuan("0.2", 0, 1000000000, &cents) && cents == 20,
                "pad one decimal place");
    ok &= check(money_parse_yuan("10000000.00", 0, 1000000000, &cents) &&
                cents == 1000000000, "accept configured maximum");
    ok &= check(!money_parse_yuan("10000000.01", 0, 1000000000, &cents),
                "reject value above maximum");
    ok &= check(!money_parse_yuan("0.001", 0, 1000000000, &cents),
                "reject fraction smaller than one fen");
    ok &= check(!money_parse_yuan("-0.01", 0, 1000000000, &cents),
                "reject negative amount");
    ok &= check(!money_parse_yuan("1e2", 0, 1000000000, &cents),
                "reject exponent notation");
    ok &= check(!money_parse_yuan("1.", 0, 1000000000, &cents),
                "reject empty fractional part");

    int64_t integer = 0;
    ok &= check(money_parse_json_integer(" 123456, ", &integer) && integer == 123456,
                "parse JSON integer cents");
    ok &= check(money_parse_json_integer("-1}", &integer) && integer == -1,
                "parse negative integer for range validation");
    ok &= check(!money_parse_json_integer("12.0", &integer),
                "reject non-integer JSON number");
    ok &= check(!money_parse_json_integer("1e2", &integer),
                "reject exponent JSON number");
    ok &= check(!money_parse_json_integer("+1", &integer),
                "reject plus sign in JSON number");
    ok &= check(!money_parse_json_integer("01", &integer),
                "reject leading zero in JSON number");
    ok &= check(!money_parse_json_integer("9223372036854775808}", &integer),
                "reject integer overflow");

    return ok ? 0 : 1;
}
