#ifndef CAMPUS_FINANCE_MONEY_H
#define CAMPUS_FINANCE_MONEY_H

#include <stdbool.h>
#include <stdint.h>

bool money_parse_yuan(const char *text, int64_t minimum_cents,
                      int64_t maximum_cents, int64_t *cents);
bool money_parse_json_integer(const char *text, int64_t *value);

#endif
