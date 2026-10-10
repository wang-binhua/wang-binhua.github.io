#define _POSIX_C_SOURCE 200809L
#include "../src/security.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define make_dir(path) _mkdir(path)
#define change_dir(path) _chdir(path)
#define remove_dir(path) _rmdir(path)
#define file_exists(path) (_access(path, 0) == 0)
#else
#include <sys/stat.h>
#include <unistd.h>
#define make_dir(path) mkdir(path, 0700)
#define change_dir(path) chdir(path)
#define remove_dir(path) rmdir(path)
#define file_exists(path) (access(path, F_OK) == 0)
#endif

static sqlite3 *database;
#ifdef _WIN32
static char work_dir[MAX_PATH], original_dir[MAX_PATH];
#else
static char work_dir[512], original_dir[512];
#endif

static int check(int condition, const char *message) {
    if (condition) return 1;
    fprintf(stderr, "FAIL: %s\n", message);
    return 0;
}

static long long read_available_balance(void) {
    sqlite3_stmt *statement = NULL;
    const char *sql =
        "SELECT b.amount_cents+COALESCE(SUM(CASE WHEN t.type='income' THEN t.amount_cents ELSE -t.amount_cents END),0) "
        "FROM balance_state b LEFT JOIN transactions t ON t.id>b.through_transaction_id WHERE b.id=1";
    if (sqlite3_prepare_v2(database, sql, -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    long long amount = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    return amount;
}

static int copy_file(const char *source, const char *destination) {
    FILE *input = fopen(source, "rb");
    if (!input) return 0;
    FILE *output = fopen(destination, "wb");
    if (!output) {
        fclose(input);
        return 0;
    }
    char buffer[4096];
    size_t count;
    int ok = 1;
    while ((count = fread(buffer, 1, sizeof buffer, input)) != 0) {
        if (fwrite(buffer, 1, count, output) != count) {
            ok = 0;
            break;
        }
    }
    if (ferror(input)) ok = 0;
    if (fclose(input) != 0) ok = 0;
    if (fclose(output) != 0) ok = 0;
    if (!ok) remove(destination);
    return ok;
}

static void cleanup(void) {
    if (database) sqlite3_close(database);
    database = NULL;
    const char *files[] = {
        "data/finance.db", "data/legacy-copy.db", "data/finance.db-journal", "data/finance.db-wal",
        "data/finance.db-shm", "data/credentials.bin", "data/credentials.tmp",
        "data/finance.db.encrypted.tmp"
    };
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) remove(files[i]);
    remove_dir("data");
    change_dir(original_dir);
#ifdef _WIN32
    RemoveDirectoryA(work_dir);
#else
    remove_dir(work_dir);
#endif
}

int main(void) {
#ifdef _WIN32
    DWORD path_length = GetCurrentDirectoryA(sizeof original_dir, original_dir);
    char temp_path[MAX_PATH];
    if (!path_length || path_length >= sizeof original_dir ||
        !GetTempPathA(sizeof temp_path, temp_path) ||
        !GetTempFileNameA(temp_path, "cfs", 0, work_dir)) return 1;
    DeleteFileA(work_dir);
    if (!CreateDirectoryA(work_dir, NULL)) return 1;
#else
    if (!getcwd(original_dir, sizeof original_dir)) return 1;
    snprintf(work_dir, sizeof work_dir, "/tmp/campus-finance-security-XXXXXX");
    if (!mkdtemp(work_dir)) return 1;
#endif
    if (atexit(cleanup) != 0 || change_dir(work_dir) != 0 || make_dir("data") != 0) return 1;
    if (!check(sqlite3_open("data/finance.db", &database) == SQLITE_OK,
               "create legacy database")) return 1;
    const char *schema =
        "CREATE TABLE categories(id INTEGER PRIMARY KEY,name TEXT NOT NULL,type TEXT NOT NULL);"
        "CREATE TABLE transactions(id INTEGER PRIMARY KEY,record_date TEXT NOT NULL,type TEXT NOT NULL,category_id INTEGER NOT NULL,amount_cents INTEGER NOT NULL,note TEXT NOT NULL DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE budgets(month TEXT NOT NULL,category_id INTEGER NOT NULL,amount_cents INTEGER NOT NULL,PRIMARY KEY(month,category_id));"
        "INSERT INTO categories VALUES(1,'餐饮','expense');"
        "INSERT INTO transactions(id,record_date,type,category_id,amount_cents,note) VALUES(41,'2026-10-05','expense',1,1234,'legacy entry');";
    int seeded = sqlite3_exec(database, schema, NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(database);
    database = NULL;
    if (!check(seeded, "seed legacy record")) return 1;
    if (!check(copy_file("data/finance.db", "data/legacy-copy.db"), "save disposable migration fixture"))
        return 1;

    char recovery[65] = {0}, error[256] = {0};
    if (!check(security_create_database("correct horse battery staple",
                                        recovery, sizeof recovery, &database,
                                        error, sizeof error),
               error[0] ? error : "initialize and migrate database")) return 1;

    sqlite3_stmt *statement = NULL;
    int preserved = sqlite3_prepare_v2(database,
        "SELECT amount_cents,note FROM transactions WHERE id=41", -1,
        &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW &&
        sqlite3_column_int(statement, 0) == 1234 &&
        strcmp((const char *)sqlite3_column_text(statement, 1), "legacy entry") == 0;
    sqlite3_finalize(statement);
    int no_plaintext_backup = !file_exists("data/finance.db.migration.bak");
    security_close_database(database);
    database = NULL;
    if (!check(preserved, "preserve legacy data")) return 1;
    if (!check(no_plaintext_backup, "do not leave a plaintext migration backup")) return 1;
    if (!check(strlen(recovery) == 64, "generate a 256-bit recovery key")) return 1;

    security_close_database(database);
    database = NULL;
    FILE *credentials = fopen("data/credentials.bin", "r+b");
    int pending_written = 0;
    if (credentials) {
        pending_written = fseek(credentials, 9, SEEK_SET) == 0 &&
                          fputc(1, credentials) != EOF;
        if (fclose(credentials) != 0) pending_written = 0;
    }
    if (!check(pending_written, "mark simulated interrupted migration")) return 1;
    bool used_recovery = false;
    if (!check(security_unlock_database("correct horse battery staple",
                                        &database, &used_recovery, error, sizeof error),
               "resume after encrypted database replacement")) return 1;
    security_close_database(database);
    database = NULL;
    credentials = fopen("data/credentials.bin", "r+b");
    pending_written = 0;
    if (credentials) {
        pending_written = fseek(credentials, 9, SEEK_SET) == 0 &&
                          fputc(1, credentials) != EOF;
        if (fclose(credentials) != 0) pending_written = 0;
    }
    if (!check(pending_written, "mark simulated pre-replacement interruption")) return 1;
    if (!check(copy_file("data/legacy-copy.db", "data/finance.db"),
               "restore disposable plaintext fixture for interrupted migration")) return 1;
    int resumed = security_unlock_database("correct horse battery staple",
                                           &database, &used_recovery, error, sizeof error);
    if (!resumed) fprintf(stderr, "Migration recovery detail: %s\n", error);
    if (!check(resumed, "resume interrupted migration without losing access")) return 1;
    sqlite3_close(database);
    database = NULL;

    FILE *file = fopen("data/finance.db", "rb");
    char header[16] = {0};
    int encrypted = file && fread(header, 1, 16, file) == 16 &&
                    memcmp(header, "SQLite format 3", 15) != 0;
    if (file) fclose(file);
    if (!check(encrypted, "database file does not expose the SQLite plaintext header")) return 1;

    if (!check(!security_unlock_database("wrong password", &database, &used_recovery, error, sizeof error),
               "reject incorrect password")) return 1;
    if (!check(security_unlock_database("correct horse battery staple",
                                        &database, &used_recovery, error, sizeof error),
               "accept correct password")) return 1;
    security_close_database(database);
    database = NULL;
    char rotated_recovery[65] = {0};
    if (!check(security_reset_password(recovery, "new correct horse battery staple",
                                       rotated_recovery, sizeof rotated_recovery,
                                       error, sizeof error),
               "reset password with recovery key")) return 1;
    if (!check(strlen(rotated_recovery) == 64, "rotate the recovery key")) return 1;
    if (!check(!security_unlock_database(recovery, &database, &used_recovery,
                                         error, sizeof error),
               "revoke the old recovery key")) return 1;
    if (!check(!security_unlock_database("correct horse battery staple",
                                        &database, &used_recovery, error, sizeof error),
               "reject old password after reset")) return 1;
    if (!check(security_unlock_database("new correct horse battery staple",
                                        &database, &used_recovery, error, sizeof error),
               "accept reset password")) return 1;
    security_close_database(database);
    database = NULL;
    if (!check(security_unlock_database(rotated_recovery, &database, &used_recovery, error, sizeof error) &&
               used_recovery,
               "rotated recovery key unlocks database")) return 1;
    security_close_database(database);
    database = NULL;
    credentials = fopen("data/credentials.bin", "r+b");
    pending_written = 0;
    if (credentials) {
        pending_written = fseek(credentials, 9, SEEK_SET) == 0 &&
                          fputc(1, credentials) != EOF &&
                          fputc(0, credentials) != EOF;
        if (fclose(credentials) != 0) pending_written = 0;
    }
    if (!check(pending_written, "mark simulated first-run interruption")) return 1;
    if (!check(remove("data/finance.db") == 0, "simulate interrupted empty-database creation"))
        return 1;
    if (!check(security_unlock_database("new correct horse battery staple",
                                        &database, &used_recovery, error, sizeof error),
               "resume interrupted first-run database creation")) return 1;
    const char *balance_schema =
        "CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY,name TEXT NOT NULL,type TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY,record_date TEXT NOT NULL,type TEXT NOT NULL,category_id INTEGER NOT NULL,amount_cents INTEGER NOT NULL,note TEXT NOT NULL DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS balance_state(id INTEGER PRIMARY KEY CHECK(id=1),amount_cents INTEGER NOT NULL CHECK(amount_cents>=0),through_transaction_id INTEGER NOT NULL DEFAULT 0);"
        "DELETE FROM transactions;DELETE FROM categories;DELETE FROM balance_state;"
        "INSERT INTO categories VALUES(1,'Food','expense'),(2,'Income','income');"
        "INSERT INTO transactions(id,record_date,type,category_id,amount_cents) VALUES(41,'2026-10-05','expense',1,1234);"
        "INSERT INTO balance_state VALUES(1,0,0);";
    if (!check(sqlite3_exec(database, balance_schema, NULL, NULL, NULL) == SQLITE_OK,
               "create balance snapshot fixture")) return 1;
    if (!check(read_available_balance() == -1234,
               "include existing ledger records before initial calibration")) return 1;
    if (!check(sqlite3_exec(database,
        "UPDATE balance_state SET amount_cents=500000,through_transaction_id=(SELECT MAX(id) FROM transactions) WHERE id=1;"
        "INSERT INTO transactions(id,record_date,type,category_id,amount_cents) "
        "SELECT MAX(COALESCE((SELECT MAX(id) FROM transactions),0),through_transaction_id)+1,'2026-10-06','expense',1,2500 FROM balance_state WHERE id=1;",
        NULL, NULL, NULL) == SQLITE_OK && read_available_balance() == 497500,
        "anchor current balance without deducting already-recorded expenses")) return 1;
    if (!check(sqlite3_exec(database,
        "INSERT INTO transactions(id,record_date,type,category_id,amount_cents) "
        "SELECT MAX(COALESCE((SELECT MAX(id) FROM transactions),0),through_transaction_id)+1,'2026-10-07','income',2,10000 FROM balance_state WHERE id=1;",
        NULL, NULL, NULL) == SQLITE_OK && read_available_balance() == 507500,
        "apply subsequent income to current balance")) return 1;
    if (!check(sqlite3_exec(database,
        "UPDATE balance_state SET amount_cents=300000,through_transaction_id=(SELECT MAX(id) FROM transactions) WHERE id=1;"
        "DELETE FROM transactions WHERE id>41;"
        "INSERT INTO transactions(id,record_date,type,category_id,amount_cents) "
        "SELECT MAX(COALESCE((SELECT MAX(id) FROM transactions),0),through_transaction_id)+1,'2026-10-08','expense',1,500 FROM balance_state WHERE id=1;",
        NULL, NULL, NULL) == SQLITE_OK && read_available_balance() == 299500,
        "recalibrate balance and keep future IDs above the snapshot")) return 1;
    sqlite3_close(database);
    database = NULL;
    puts("PASS migration, encryption, password recovery, and current balance snapshots");
    return 0;
}
