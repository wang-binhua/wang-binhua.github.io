#define _CRT_SECURE_NO_WARNINGS
#include "security.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <windows.h>
#define ACCESS _access
#define UNLINK _unlink
#define make_dir(path) _mkdir(path)
#else
#include <sys/stat.h>
#include <unistd.h>
#define ACCESS access
#define UNLINK unlink
#define make_dir(path) mkdir(path, 0700)
#endif

#define KEY_SIZE 32
#define SALT_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define SLOT_SIZE (SALT_SIZE + NONCE_SIZE + TAG_SIZE + KEY_SIZE)
#define FILE_SIZE (12 + SLOT_SIZE * 2)
#define KDF_ITERATIONS 600000

static const unsigned char file_magic[8] = {'C','F','K','E','Y','0','1',0};

static int replace_file(const char *source, const char *destination) {
#ifdef _WIN32
    return MoveFileExA(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return rename(source, destination) == 0;
#endif
}

static void set_error(char *error, size_t size, const char *message) {
    if (size) snprintf(error, size, "%s", message);
}

static void data_path(char *out, size_t size, const char *name) {
    snprintf(out, size, "data/%s", name);
}

static int derive_key(const char *password, const unsigned char salt[SALT_SIZE],
                      unsigned char key[KEY_SIZE]) {
    size_t length = strlen(password);
    return length <= 1024 &&
           PKCS5_PBKDF2_HMAC(password, (int)length, salt, SALT_SIZE,
                             KDF_ITERATIONS, EVP_sha256(), KEY_SIZE, key) == 1;
}

static int wrap_key(const char *password, const unsigned char master[KEY_SIZE],
                    unsigned char slot[SLOT_SIZE]) {
    unsigned char derived[KEY_SIZE];
    if (RAND_bytes(slot, SALT_SIZE) != 1 ||
        RAND_bytes(slot + SALT_SIZE, NONCE_SIZE) != 1 ||
        !derive_key(password, slot, derived)) {
        OPENSSL_cleanse(derived, sizeof derived);
        return 0;
    }
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int written = 0, final_written = 0;
    int ok = context &&
        EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) == 1 &&
        EVP_EncryptInit_ex(context, NULL, NULL, derived, slot + SALT_SIZE) == 1 &&
        EVP_EncryptUpdate(context, slot + SALT_SIZE + NONCE_SIZE + TAG_SIZE, &written,
                          master, KEY_SIZE) == 1 &&
        EVP_EncryptFinal_ex(context,
                            slot + SALT_SIZE + NONCE_SIZE + TAG_SIZE + written,
                            &final_written) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                            slot + SALT_SIZE + NONCE_SIZE) == 1 &&
        written + final_written == KEY_SIZE;
    EVP_CIPHER_CTX_free(context);
    OPENSSL_cleanse(derived, sizeof derived);
    return ok;
}

static int unwrap_key(const char *password, const unsigned char slot[SLOT_SIZE],
                      unsigned char master[KEY_SIZE]) {
    unsigned char derived[KEY_SIZE];
    if (!derive_key(password, slot, derived)) {
        OPENSSL_cleanse(derived, sizeof derived);
        return 0;
    }
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int written = 0, final_written = 0;
    int ok = context &&
        EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) == 1 &&
        EVP_DecryptInit_ex(context, NULL, NULL, derived, slot + SALT_SIZE) == 1 &&
        EVP_DecryptUpdate(context, master, &written,
                          slot + SALT_SIZE + NONCE_SIZE + TAG_SIZE, KEY_SIZE) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                            (void *)(slot + SALT_SIZE + NONCE_SIZE)) == 1 &&
        EVP_DecryptFinal_ex(context, master + written, &final_written) == 1 &&
        written + final_written == KEY_SIZE;
    EVP_CIPHER_CTX_free(context);
    OPENSSL_cleanse(derived, sizeof derived);
    if (!ok) OPENSSL_cleanse(master, KEY_SIZE);
    return ok;
}

static int read_keyring(unsigned char keyring[FILE_SIZE]) {
    char path[64];
    data_path(path, sizeof path, "credentials.bin");
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    int ok = fread(keyring, 1, FILE_SIZE, file) == FILE_SIZE &&
             fgetc(file) == EOF && memcmp(keyring, file_magic, sizeof file_magic) == 0 &&
             keyring[8] == 1 && keyring[9] <= 1 && keyring[10] <= 1 && keyring[11] == 0;
    fclose(file);
    return ok;
}

static int write_keyring(const unsigned char keyring[FILE_SIZE]) {
    char path[64], temporary[72];
    data_path(path, sizeof path, "credentials.bin");
    data_path(temporary, sizeof temporary, "credentials.tmp");
    FILE *file = fopen(temporary, "wb");
    if (!file) return 0;
    int ok = fwrite(keyring, 1, FILE_SIZE, file) == FILE_SIZE && fflush(file) == 0;
    if (fclose(file) != 0) ok = 0;
    if (!ok || !replace_file(temporary, path)) {
        UNLINK(temporary);
        return 0;
    }
    return 1;
}

static int open_encrypted(const char *path, const unsigned char master[KEY_SIZE],
                          sqlite3 **database) {
    char hex[KEY_SIZE * 2 + 1];
    for (size_t i = 0; i < KEY_SIZE; i++) snprintf(hex + i * 2, 3, "%02x", master[i]);
    if (sqlite3_open(path, database) != SQLITE_OK) {
        if (*database) sqlite3_close(*database);
        *database = NULL;
        return 0;
    }
    char pragma[96];
    snprintf(pragma, sizeof pragma, "x'%s'", hex);
    if (sqlite3_key(*database, pragma, (int)strlen(pragma)) != SQLITE_OK) {
        sqlite3_close(*database);
        *database = NULL;
        OPENSSL_cleanse(hex, sizeof hex);
        return 0;
    }
    if (sqlite3_exec(*database, "PRAGMA cipher_memory_security = ON;", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(*database);
        *database = NULL;
        OPENSSL_cleanse(hex, sizeof hex);
        return 0;
    }
    sqlite3_stmt *statement = NULL;
    int ok = sqlite3_prepare_v2(*database, "SELECT count(*) FROM sqlite_master", -1,
                                &statement, NULL) == SQLITE_OK &&
             sqlite3_step(statement) == SQLITE_ROW;
    sqlite3_finalize(statement);
    OPENSSL_cleanse(hex, sizeof hex);
    if (!ok) {
        sqlite3_close(*database);
        *database = NULL;
    }
    return ok;
}

static int export_plain_database(const char *source, const char *temporary,
                                 const unsigned char master[KEY_SIZE]) {
    char hex[KEY_SIZE * 2 + 1], attach[256];
    for (size_t i = 0; i < KEY_SIZE; i++) snprintf(hex + i * 2, 3, "%02x", master[i]);
    sqlite3 *database = NULL;
    int ok = sqlite3_open(source, &database) == SQLITE_OK;
    if (ok) {
        snprintf(attach, sizeof attach, "ATTACH DATABASE '%s' AS encrypted KEY \"x'%s'\"",
                 temporary, hex);
        ok = sqlite3_exec(database, attach, NULL, NULL, NULL) == SQLITE_OK &&
             sqlite3_exec(database, "SELECT sqlcipher_export('encrypted')", NULL, NULL, NULL) == SQLITE_OK &&
             sqlite3_exec(database, "DETACH DATABASE encrypted", NULL, NULL, NULL) == SQLITE_OK;
    }
    if (database) sqlite3_close(database);
    OPENSSL_cleanse(hex, sizeof hex);
    OPENSSL_cleanse(attach, sizeof attach);
    if (!ok) UNLINK(temporary);
    return ok;
}

static int create_empty_database(const char *path, const unsigned char master[KEY_SIZE]) {
    sqlite3 *database = NULL;
    if (!open_encrypted(path, master, &database)) return 0;
    int ok = sqlite3_exec(database,
        "CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY,name TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN('income','expense')),UNIQUE(name,type));"
        "CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY,record_date TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN('income','expense')),category_id INTEGER NOT NULL REFERENCES categories(id),amount_cents INTEGER NOT NULL CHECK(amount_cents>0),note TEXT NOT NULL DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS budgets(month TEXT NOT NULL,category_id INTEGER NOT NULL REFERENCES categories(id),amount_cents INTEGER NOT NULL CHECK(amount_cents>=0),PRIMARY KEY(month,category_id));"
        "CREATE INDEX IF NOT EXISTS transaction_month ON transactions(record_date);"
        "INSERT OR IGNORE INTO categories(name,type) VALUES('生活费','income'),('奖学金','income'),('兼职','income'),('退款','income'),('餐饮','expense'),('交通','expense'),('学习','expense'),('住宿','expense'),('日用品','expense'),('娱乐','expense'),('医疗','expense'),('通讯','expense');",
        NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(database);
    return ok;
}

static int create_encrypted_copy(const char *source, const unsigned char master[KEY_SIZE],
                                 char *error, size_t error_size) {
    char temporary[80];
    data_path(temporary, sizeof temporary, "finance.db.encrypted.tmp");
    if (ACCESS(temporary, 0) == 0) UNLINK(temporary);
    int ok;
    if (ACCESS(source, 0) == 0) {
        ok = export_plain_database(source, temporary, master);
        if (!ok) set_error(error, error_size, "Could not migrate the existing database; the original was not changed.");
    } else {
        ok = create_empty_database(temporary, master);
        if (!ok) set_error(error, error_size, "Could not create the encrypted database.");
    }
    if (!ok) {
        UNLINK(temporary);
        return 0;
    }
    sqlite3 *verification = NULL;
    ok = open_encrypted(temporary, master, &verification);
    if (verification) sqlite3_close(verification);
    if (!ok) {
        UNLINK(temporary);
        set_error(error, error_size, "Encrypted database verification failed; the original was not changed.");
        return 0;
    }
    if (!replace_file(temporary, source)) {
        UNLINK(temporary);
        set_error(error, error_size, "Could not atomically install the encrypted database; the original was not changed.");
        return 0;
    }
    UNLINK("data/finance.db-wal");
    UNLINK("data/finance.db-shm");
    UNLINK("data/finance.db-journal");
    return 1;
}

static int is_plaintext_database(const char *path) {
    static const char sqlite_header[] = "SQLite format 3";
    char header[sizeof sqlite_header - 1];
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    int is_plaintext = fread(header, 1, sizeof header, file) == sizeof header &&
                       memcmp(header, sqlite_header, sizeof header) == 0;
    fclose(file);
    return is_plaintext;
}

static int has_expected_schema(sqlite3 *database) {
    sqlite3_stmt *statement = NULL;
    int ok = sqlite3_prepare_v2(database,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='categories'",
        -1, &statement, NULL) == SQLITE_OK && sqlite3_step(statement) == SQLITE_ROW;
    sqlite3_finalize(statement);
    return ok;
}

bool security_is_initialized(void) {
    char path[64];
    data_path(path, sizeof path, "credentials.bin");
    return ACCESS(path, 0) == 0;
}

int security_create_database(const char *password, char *recovery_key, size_t recovery_key_size,
                             sqlite3 **database, char *error, size_t error_size) {
    unsigned char existing[FILE_SIZE], keyring[FILE_SIZE] = {0}, master[KEY_SIZE], recovery[KEY_SIZE];
    if (ACCESS("data/finance.db.migration.bak", 0) == 0 &&
        ACCESS("data/finance.db", 0) != 0 &&
        !replace_file("data/finance.db.migration.bak", "data/finance.db")) {
        set_error(error, error_size, "Could not restore the interrupted plaintext migration; no data was changed.");
        return 0;
    }
    if (security_is_initialized()) {
        set_error(error, error_size, "Credentials already exist.");
        return 0;
    }
    if (strlen(password) < 12) {
        set_error(error, error_size, "Use a password with at least 12 characters.");
        return 0;
    }
    if (read_keyring(existing)) {
        set_error(error, error_size, "Credentials already exist.");
        return 0;
    }
    if (RAND_bytes(master, sizeof master) != 1 || RAND_bytes(recovery, sizeof recovery) != 1) {
        set_error(error, error_size, "Secure random key generation failed.");
        return 0;
    }
    if (recovery_key_size < sizeof recovery * 2 + 1) {
        set_error(error, error_size, "Recovery key output buffer is too small.");
        goto fail;
    }
    for (size_t i = 0; i < sizeof recovery; i++) snprintf(recovery_key + i * 2, 3, "%02X", recovery[i]);
    memcpy(keyring, file_magic, sizeof file_magic);
    keyring[8] = 1;
    keyring[9] = 1;
    keyring[10] = ACCESS("data/finance.db", 0) == 0 ? 1 : 0;
    if (!wrap_key(password, master, keyring + 12) ||
        !wrap_key(recovery_key, master, keyring + 12 + SLOT_SIZE)) goto fail;
    if (!write_keyring(keyring)) {
        set_error(error, error_size, "Could not save encryption credentials; the original database was not changed.");
        goto fail;
    }
    if (!create_encrypted_copy("data/finance.db", master, error, error_size)) goto fail;
    if (!open_encrypted("data/finance.db", master, database) || !has_expected_schema(*database)) {
        if (*database) { sqlite3_close(*database); *database = NULL; }
        set_error(error, error_size, "Encrypted database verification failed; credentials are retained for safe recovery.");
        goto fail;
    }
    keyring[9] = 0;
    if (!write_keyring(keyring)) {
        set_error(error, error_size, "The encrypted database is ready, but migration status could not be finalized. Keep the recovery key.");
        goto fail;
    }
    OPENSSL_cleanse(master, sizeof master);
    OPENSSL_cleanse(recovery, sizeof recovery);
    OPENSSL_cleanse(keyring, sizeof keyring);
    return 1;
fail:
    if (database && *database) {
        sqlite3_close(*database);
        *database = NULL;
    }
    OPENSSL_cleanse(master, sizeof master);
    OPENSSL_cleanse(recovery, sizeof recovery);
    OPENSSL_cleanse(keyring, sizeof keyring);
    OPENSSL_cleanse(existing, sizeof existing);
    OPENSSL_cleanse(recovery_key, recovery_key_size);
    return 0;
}

int security_unlock_database(const char *credential, sqlite3 **database,
                             bool *used_recovery_key, char *error, size_t error_size) {
    unsigned char keyring[FILE_SIZE], master[KEY_SIZE];
    if (!read_keyring(keyring)) {
        set_error(error, error_size, "Credential file is missing or invalid.");
        return 0;
    }
    int recovery = 0;
    int ok = unwrap_key(credential, keyring + 12, master);
    if (!ok) {
        recovery = 1;
        ok = unwrap_key(credential, keyring + 12 + SLOT_SIZE, master);
    }
    if (!ok) {
        OPENSSL_cleanse(keyring, sizeof keyring);
        set_error(error, error_size, "Incorrect password or recovery key.");
        return 0;
    }
    if (ACCESS("data/finance.db", 0) != 0 && !(keyring[9] == 1 && keyring[10] == 0)) {
        OPENSSL_cleanse(master, sizeof master);
        OPENSSL_cleanse(keyring, sizeof keyring);
        set_error(error, error_size, "Database file is missing; refusing to create a replacement.");
        return 0;
    }
    if (keyring[9] == 1) {
        if (ACCESS("data/finance.db", 0) != 0) {
            ok = keyring[10] == 0 &&
                 create_encrypted_copy("data/finance.db", master, error, error_size) &&
                 open_encrypted("data/finance.db", master, database) &&
                 has_expected_schema(*database);
        } else {
            ok = open_encrypted("data/finance.db", master, database) &&
                 has_expected_schema(*database);
        }
        if (!ok) {
            if (*database) { sqlite3_close(*database); *database = NULL; }
            if (ACCESS("data/finance.db", 0) != 0) {
                set_error(error, error_size, "Database file is missing; refusing to create a replacement.");
            } else if (is_plaintext_database("data/finance.db")) {
                ok = create_encrypted_copy("data/finance.db", master, error, error_size) &&
                     open_encrypted("data/finance.db", master, database) &&
                     has_expected_schema(*database);
            }
        }
        if (ok) {
            keyring[9] = 0;
            if (!write_keyring(keyring)) {
                sqlite3_close(*database);
                *database = NULL;
                ok = 0;
                set_error(error, error_size, "Could not finalize database migration state.");
            }
        }
    } else {
        ok = open_encrypted("data/finance.db", master, database) &&
             has_expected_schema(*database);
        if (!ok && *database) { sqlite3_close(*database); *database = NULL; }
    }
    OPENSSL_cleanse(master, sizeof master);
    OPENSSL_cleanse(keyring, sizeof keyring);
    if (!ok && error_size && !error[0])
        set_error(error, error_size, "Could not unlock the encrypted database.");
    if (ok) {
        UNLINK("data/finance.db.migration.bak");
        if (used_recovery_key) *used_recovery_key = recovery != 0;
    }
    return ok;
}

int security_reset_password(const char *recovery_key, const char *new_password,
                            char *new_recovery_key, size_t new_recovery_key_size,
                            char *error, size_t error_size) {
    unsigned char keyring[FILE_SIZE], master[KEY_SIZE], recovery[KEY_SIZE];
    if (strlen(new_password) < 12) {
        set_error(error, error_size, "Use a password with at least 12 characters.");
        return 0;
    }
    if (new_recovery_key_size < sizeof recovery * 2 + 1) {
        set_error(error, error_size, "Recovery key output buffer is too small.");
        return 0;
    }
    if (!read_keyring(keyring) ||
        !unwrap_key(recovery_key, keyring + 12 + SLOT_SIZE, master) ||
        RAND_bytes(recovery, sizeof recovery) != 1) {
        OPENSSL_cleanse(keyring, sizeof keyring);
        OPENSSL_cleanse(master, sizeof master);
        OPENSSL_cleanse(recovery, sizeof recovery);
        set_error(error, error_size, "Incorrect recovery key.");
        return 0;
    }
    for (size_t i = 0; i < sizeof recovery; i++)
        snprintf(new_recovery_key + i * 2, 3, "%02X", recovery[i]);
    unsigned char updated[FILE_SIZE];
    memcpy(updated, keyring, sizeof updated);
    int ok = wrap_key(new_password, master, updated + 12) &&
             wrap_key(new_recovery_key, master, updated + 12 + SLOT_SIZE);
    OPENSSL_cleanse(master, sizeof master);
    if (!ok || !write_keyring(updated)) {
        OPENSSL_cleanse(keyring, sizeof keyring);
        OPENSSL_cleanse(updated, sizeof updated);
        OPENSSL_cleanse(recovery, sizeof recovery);
        OPENSSL_cleanse(new_recovery_key, new_recovery_key_size);
        set_error(error, error_size, "Could not save the new password.");
        return 0;
    }
    OPENSSL_cleanse(keyring, sizeof keyring);
    OPENSSL_cleanse(updated, sizeof updated);
    OPENSSL_cleanse(recovery, sizeof recovery);
    return 1;
}

void security_close_database(sqlite3 *database) {
    if (database) sqlite3_close(database);
}
