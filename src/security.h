#ifndef CAMPUS_FINANCE_SECURITY_H
#define CAMPUS_FINANCE_SECURITY_H

#include <stdbool.h>
#include <stddef.h>
#include <sqlite3.h>

bool security_is_initialized(void);
int security_create_database(const char *password, char *recovery_key, size_t recovery_key_size,
                             sqlite3 **database, char *error, size_t error_size);
int security_unlock_database(const char *credential, sqlite3 **database,
                             bool *used_recovery_key, char *error, size_t error_size);
int security_reset_password(const char *recovery_key, const char *new_password,
                            char *new_recovery_key, size_t new_recovery_key_size,
                            char *error, size_t error_size);
void security_close_database(sqlite3 *database);

#endif
