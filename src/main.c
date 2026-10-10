/* A local-only personal finance server: C17 + sockets + SQLite. */
#define _CRT_SECURE_NO_WARNINGS
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "security.h"
#include "money.h"
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define CLOSE_SOCKET closesocket
#define make_dir(p) _mkdir(p)
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSE_SOCKET close
#define make_dir(p) mkdir(p, 0755)
#endif

#define PORT 8080
#define REQUEST_MAX 65536
#define RESPONSE_MAX 131072
static sqlite3 *database;

typedef struct { char method[8], path[256], query[256], session[65]; const char *body; } Request;

static void append(char *out, size_t cap, size_t *at, const char *fmt, ...) {
    if (*at >= cap) return;
    va_list args; va_start(args, fmt);
    int n = vsnprintf(out + *at, cap - *at, fmt, args);
    va_end(args);
    if (n > 0 && (size_t)n < cap - *at) *at += (size_t)n;
}
static char session_token[65];
static time_t session_expires;
static time_t login_blocked_until;
static unsigned int login_failures;
static void escape_json(char *out, size_t cap, const char *in) {
    size_t n = 0;
    while (*in && n + 3 < cap) {
        if (*in == '"' || *in == '\\') { out[n++]='\\'; out[n++]=*in++; }
        else if (*in == '\n') { out[n++]='\\'; out[n++]='n'; in++; }
        else if ((unsigned char)*in >= 32) out[n++]=*in++;
        else in++;
    } out[n] = 0;
}
static bool json_text(const char *body, const char *key, char *out, size_t cap) {
    char mark[80]; snprintf(mark, sizeof mark, "\"%s\"", key);
    const char *p = strstr(body, mark); if (!p || !(p=strchr(p+strlen(mark), ':'))) return false;
    for (++p; isspace((unsigned char)*p); p++) { }
    if (*p++ != '"') return false;
    size_t n=0; while (*p && *p != '"' && n+1<cap) { if (*p=='\\' && p[1]) p++; out[n++]=*p++; }
    out[n]=0; return *p=='"';
}
static bool json_number(const char *body, const char *key, double *value) {
    char mark[80]; snprintf(mark, sizeof mark, "\"%s\"", key);
    const char *p=strstr(body, mark); char *end;
    if (!p || !(p=strchr(p+strlen(mark), ':'))) return false;
    *value=strtod(p+1,&end); return end != p+1;
}
static bool json_integer(const char *body, const char *key, int64_t *value) {
    char mark[80]; snprintf(mark, sizeof mark, "\"%s\"", key);
    const char *p = strstr(body, mark);
    if (!p || !(p = strchr(p + strlen(mark), ':'))) return false;
    return money_parse_json_integer(p + 1, value);
}
static void query(const Request *r, const char *key, char *out, size_t cap) {
    out[0]=0; size_t len=strlen(key); const char *p=r->query;
    while (*p) { if ((p==r->query || p[-1]=='&') && !strncmp(p,key,len) && p[len]=='=') { p+=len+1; size_t n=0; while(*p && *p!='&' && n+1<cap) out[n++]=*p++; out[n]=0; return; } p++; }
}
static bool month_ok(const char *m) { return strlen(m)==7 && m[4]=='-' && m[0]>='0'&&m[0]<='9'&&m[1]>='0'&&m[1]<='9'&&m[2]>='0'&&m[2]<='9'&&m[3]>='0'&&m[3]<='9'&&m[5]>='0'&&m[5]<='1'&&m[6]>='0'&&m[6]<='9'; }
static bool date_ok(const char *d) { return strlen(d)==10 && d[4]=='-' && d[7]=='-'; }

static bool ascii_equal(const char *left, const char *right) {
    while (*left && *right) {
        if (tolower((unsigned char)*left++) != tolower((unsigned char)*right++)) return false;
    }
    return *left == 0 && *right == 0;
}
static bool request_header(const char *raw, const char *body, const char *name, char *out, size_t cap) {
    const char *line = strstr(raw, "\r\n");
    if (!line) return false;
    line += 2;
    size_t name_length = strlen(name);
    while (line < body) {
        const char *line_end = strstr(line, "\r\n");
        if (!line_end || line_end > body || line_end == line) break;
        const char *colon = memchr(line, ':', (size_t)(line_end - line));
        if (colon && (size_t)(colon - line) == name_length) {
            size_t header_name_length = (size_t)(colon - line);
            size_t i = 0;
            while (i < header_name_length &&
                   tolower((unsigned char)line[i]) == tolower((unsigned char)name[i])) i++;
            if (i != header_name_length) { line = line_end + 2; continue; }
            const char *value = colon + 1;
            while (value < line_end && (*value == ' ' || *value == '\t')) value++;
            while (line_end > value && (line_end[-1] == ' ' || line_end[-1] == '\t')) line_end--;
            size_t value_length = (size_t)(line_end - value);
            if (value_length >= cap) return false;
            memcpy(out, value, value_length);
            out[value_length] = 0;
            return true;
        }
        line = line_end + 2;
    }
    return false;
}
static void request_session(const char *cookies, char *out, size_t cap) {
    out[0] = 0;
    const char *position = cookies;
    while (*position) {
        while (*position == ' ' || *position == ';' || *position == '\t') position++;
        if (!strncmp(position, "CFSESSION=", 10)) {
            position += 10;
            size_t length = 0;
            while (position[length] && position[length] != ';' && position[length] != ' ' &&
                   position[length] != '\t' && length + 1 < cap) length++;
            if (length == 64) {
                memcpy(out, position, length);
                out[length] = 0;
            }
            return;
        }
        const char *separator = strchr(position, ';');
        if (!separator) return;
        position = separator + 1;
    }
}
static bool local_host(const char *host) {
    return ascii_equal(host, "127.0.0.1:8080");
}
static bool trusted_origin(const char *origin, const char *host) {
    return ascii_equal(host, "127.0.0.1:8080") && ascii_equal(origin, "http://127.0.0.1:8080");
}
static bool json_content_type(const char *value) {
    static const char expected[] = "application/json";
    size_t length = sizeof expected - 1;
    if (strlen(value) < length) return false;
    for (size_t i = 0; i < length; i++)
        if (tolower((unsigned char)value[i]) != expected[i]) return false;
    return value[length] == 0 || value[length] == ';' || isspace((unsigned char)value[length]);
}
static void csv_field(char *out, size_t cap, size_t *at, const char *value) {
    const unsigned char *first = (const unsigned char *)value;
    while (*first == ' ' || *first == '\t' || *first == '\r' || *first == '\n') first++;
    bool formula = *first == '=' || *first == '+' || *first == '-' || *first == '@';
    append(out, cap, at, "\"");
    if (formula) append(out, cap, at, "'");
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"') append(out, cap, at, "\"\"");
        else append(out, cap, at, "%c", *p);
    }
    append(out, cap, at, "\"");
}

static void reply(socket_t s, int code, const char *type, const char *body, size_t size) {
    const char *reason=code==200?"OK":code==201?"Created":code==204?"No Content":code==400?"Bad Request":code==401?"Unauthorized":code==403?"Forbidden":code==404?"Not Found":code==409?"Conflict":code==415?"Unsupported Media Type":code==429?"Too Many Requests":"Server Error";
    char header[512]; int n=snprintf(header,sizeof header,"HTTP/1.1 %d %s\r\nContent-Type: %s; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",code,reason,type,size);
    send(s,header,n,0); if(size) send(s,body,(int)size,0);
}
static void reply_cookie(socket_t s, const char *body, const char *cookie) {
    char header[640];
    int n = snprintf(header, sizeof header,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %zu\r\nConnection: close\r\nCache-Control: no-store\r\n"
        "Set-Cookie: CFSESSION=%s; HttpOnly; SameSite=Strict; Path=/\r\n\r\n",
        strlen(body), cookie);
    send(s, header, n, 0);
    send(s, body, (int)strlen(body), 0);
}
static void clear_cookie(socket_t s) {
    const char *header =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
        "Content-Length: 11\r\nConnection: close\r\nCache-Control: no-store\r\n"
        "Set-Cookie: CFSESSION=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0\r\n\r\n"
        "{\"ok\":true}";
    send(s, header, (int)strlen(header), 0);
}
static void json(socket_t s, int code, const char *body) { reply(s,code,"application/json",body,strlen(body)); }
static void error(socket_t s, int code, const char *message) { char e[256],body[300]; escape_json(e,sizeof e,message); snprintf(body,sizeof body,"{\"error\":\"%s\"}",e); json(s,code,body); }

static bool setup_database(void) {
    make_dir("data");
    if(!database) return false;
    const char *schema=
      "PRAGMA foreign_keys=ON;"
      "CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY,name TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN('income','expense')),UNIQUE(name,type));"
      "CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY,record_date TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN('income','expense')),category_id INTEGER NOT NULL REFERENCES categories(id),amount_cents INTEGER NOT NULL CHECK(amount_cents>0),note TEXT NOT NULL DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);"
      "CREATE TABLE IF NOT EXISTS budgets(month TEXT NOT NULL,category_id INTEGER NOT NULL REFERENCES categories(id),amount_cents INTEGER NOT NULL CHECK(amount_cents>=0),PRIMARY KEY(month,category_id));"
      "CREATE TABLE IF NOT EXISTS balance_state(id INTEGER PRIMARY KEY CHECK(id=1),amount_cents INTEGER NOT NULL CHECK(amount_cents>=0),through_transaction_id INTEGER NOT NULL DEFAULT 0);"
      "INSERT OR IGNORE INTO balance_state(id,amount_cents,through_transaction_id) VALUES(1,0,0);"
      "CREATE INDEX IF NOT EXISTS transaction_month ON transactions(record_date);"
      "INSERT OR IGNORE INTO categories(name,type) VALUES('生活费','income'),('奖学金','income'),('兼职','income'),('退款','income'),('餐饮','expense'),('交通','expense'),('学习','expense'),('住宿','expense'),('日用品','expense'),('娱乐','expense'),('医疗','expense'),('通讯','expense');";
    return sqlite3_exec(database,schema,0,0,0)==SQLITE_OK;
}

static bool start_session(socket_t s, const char *credential, const char *rotated_recovery) {
    char error_message[256] = {0};
    bool used_recovery = false;
    sqlite3 *opened = NULL;
    if (!security_unlock_database(credential, &opened, &used_recovery,
                                  error_message, sizeof error_message)) {
        error(s, 401, error_message);
        return false;
    }
    if (used_recovery) {
        security_close_database(opened);
        error(s, 401, "Use the recovery form to reset your password.");
        return false;
    }
    if (database) security_close_database(database);
    OPENSSL_cleanse(session_token, sizeof session_token);
    session_expires = 0;
    database = opened;
    if (!setup_database()) {
        security_close_database(database);
        database = NULL;
        error(s, 500, "Could not initialize the encrypted database schema.");
        return false;
    }
    unsigned char random[32];
    if (RAND_bytes(random, sizeof random) != 1) {
        security_close_database(database);
        database = NULL;
        error(s, 500, "Could not create a secure session.");
        return false;
    }
    for (size_t i = 0; i < sizeof random; i++)
        snprintf(session_token + i * 2, 3, "%02x", random[i]);
    OPENSSL_cleanse(random, sizeof random);
    session_expires = time(NULL) + 15 * 60;
    login_failures = 0;
    login_blocked_until = 0;
    char body[160];
    if (rotated_recovery)
        snprintf(body, sizeof body, "{\"ok\":true,\"recoveryKey\":\"%s\"}", rotated_recovery);
    else
        snprintf(body, sizeof body, "{\"ok\":true}");
    reply_cookie(s, body, session_token);
    return true;
}

static void auth_status(socket_t s) {
    char body[64];
    snprintf(body, sizeof body, "{\"initialized\":%s}", security_is_initialized() ? "true" : "false");
    json(s, 200, body);
}

static void auth_setup(socket_t s, const Request *r) {
    if (security_is_initialized()) {
        error(s, 409, "The account is already initialized.");
        return;
    }
    char password[1024] = {0}, recovery[65] = {0}, error_message[256] = {0};
    if (!json_text(r->body, "password", password, sizeof password) || strlen(password) < 12) {
        error(s, 400, "Use a password with at least 12 characters.");
        return;
    }
    if (!security_create_database(password, recovery, sizeof recovery, &database,
                                  error_message, sizeof error_message)) {
        error(s, 500, error_message[0] ? error_message : "Could not create encrypted storage.");
        OPENSSL_cleanse(password, sizeof password);
        return;
    }
    if (!setup_database()) {
        security_close_database(database);
        database = NULL;
        error(s, 500, "Could not initialize the encrypted database schema.");
        OPENSSL_cleanse(password, sizeof password);
        OPENSSL_cleanse(recovery, sizeof recovery);
        return;
    }
    unsigned char random[32];
    if (RAND_bytes(random, sizeof random) != 1) {
        security_close_database(database);
        database = NULL;
        error(s, 500, "Could not create a secure session.");
        OPENSSL_cleanse(password, sizeof password);
        OPENSSL_cleanse(recovery, sizeof recovery);
        return;
    }
    for (size_t i = 0; i < sizeof random; i++)
        snprintf(session_token + i * 2, 3, "%02x", random[i]);
    OPENSSL_cleanse(random, sizeof random);
    session_expires = time(NULL) + 15 * 60;
    char body[160];
    snprintf(body, sizeof body, "{\"ok\":true,\"recoveryKey\":\"%s\"}", recovery);
    reply_cookie(s, body, session_token);
    OPENSSL_cleanse(password, sizeof password);
    OPENSSL_cleanse(recovery, sizeof recovery);
}

static void auth_login(socket_t s, const Request *r) {
    if (time(NULL) < login_blocked_until) {
        error(s, 429, "Too many failed attempts; wait before trying again.");
        return;
    }
    char password[1024] = {0}, error_message[256] = {0};
    if (!json_text(r->body, "password", password, sizeof password)) {
        error(s, 400, "Password is required.");
        return;
    }
    bool used_recovery = false;
    sqlite3 *opened = NULL;
    if (!security_unlock_database(password, &opened, &used_recovery,
                                  error_message, sizeof error_message)) {
        login_failures++;
        if (login_failures >= 5) {
            login_blocked_until = time(NULL) + 30;
            login_failures = 0;
        }
        OPENSSL_cleanse(password, sizeof password);
        error(s, 401, "Incorrect password.");
        return;
    }
    OPENSSL_cleanse(password, sizeof password);
    if (used_recovery) {
        security_close_database(opened);
        error(s, 401, "Use the recovery form to reset your password.");
        return;
    }
    if (database) security_close_database(database);
    OPENSSL_cleanse(session_token, sizeof session_token);
    session_expires = 0;
    database = opened;
    if (!setup_database()) {
        security_close_database(database);
        database = NULL;
        error(s, 500, "Could not initialize the encrypted database schema.");
        return;
    }
    unsigned char random[32];
    if (RAND_bytes(random, sizeof random) != 1) {
        security_close_database(database);
        database = NULL;
        error(s, 500, "Could not create a secure session.");
        return;
    }
    for (size_t i = 0; i < sizeof random; i++)
        snprintf(session_token + i * 2, 3, "%02x", random[i]);
    OPENSSL_cleanse(random, sizeof random);
    session_expires = time(NULL) + 15 * 60;
    login_failures = 0;
    login_blocked_until = 0;
    reply_cookie(s, "{\"ok\":true}", session_token);
}

static void auth_recover(socket_t s, const Request *r) {
    char recovery[1024] = {0}, password[1024] = {0}, confirmation[1024] = {0};
    char new_recovery[65] = {0};
    if (!json_text(r->body, "recoveryKey", recovery, sizeof recovery) ||
        !json_text(r->body, "password", password, sizeof password) ||
        !json_text(r->body, "confirmation", confirmation, sizeof confirmation) ||
        strcmp(password, confirmation) != 0 || strlen(password) < 12) {
        error(s, 400, "Provide the recovery key and matching new passwords (at least 12 characters).");
        goto cleanup;
    }
    if (time(NULL) < login_blocked_until) {
        error(s, 429, "Too many failed attempts; wait before trying again.");
        goto cleanup;
    }
    char error_message[256] = {0};
    sqlite3 *verified_database = NULL;
    bool verified_with_recovery = false;
    if (!security_unlock_database(recovery, &verified_database, &verified_with_recovery,
                                  error_message, sizeof error_message) || !verified_with_recovery) {
        if (verified_database) security_close_database(verified_database);
        login_failures++;
        if (login_failures >= 5) {
            login_blocked_until = time(NULL) + 30;
            login_failures = 0;
        }
        error(s, 401, "Incorrect recovery key or encrypted database unavailable.");
        goto cleanup;
    }
    security_close_database(verified_database);
    if (!security_reset_password(recovery, password, new_recovery, sizeof new_recovery,
                                 error_message, sizeof error_message)) {
        login_failures++;
        if (login_failures >= 5) {
            login_blocked_until = time(NULL) + 30;
            login_failures = 0;
        }
        error(s, 401, "Incorrect recovery key or invalid new password.");
        goto cleanup;
    }
    login_failures = 0;
    if (!start_session(s, password, new_recovery)) goto cleanup;
cleanup:
    OPENSSL_cleanse(recovery, sizeof recovery);
    OPENSSL_cleanse(password, sizeof password);
    OPENSSL_cleanse(confirmation, sizeof confirmation);
    OPENSSL_cleanse(new_recovery, sizeof new_recovery);
}

static bool session_valid(const Request *r) {
    if (!session_token[0] || strlen(r->session) != sizeof session_token - 1 ||
        time(NULL) > session_expires ||
        CRYPTO_memcmp(session_token, r->session, sizeof session_token - 1) != 0) {
        if (session_token[0] && time(NULL) > session_expires) {
            OPENSSL_cleanse(session_token, sizeof session_token);
            session_expires = 0;
            if (database) {
                security_close_database(database);
                database = NULL;
            }
        }
        return false;
    }
    session_expires = time(NULL) + 15 * 60;
    return true;
}

static void auth_logout(socket_t s) {
    OPENSSL_cleanse(session_token, sizeof session_token);
    session_expires = 0;
    if (database) {
        security_close_database(database);
        database = NULL;
    }
    clear_cookie(s);
}

static void categories(socket_t s, const Request *r) {
    char type[16]; query(r,"type",type,sizeof type);
    if(type[0] && strcmp(type,"income") && strcmp(type,"expense")) { error(s,400,"invalid type"); return; }
    sqlite3_stmt *st; const char *sql=type[0]?"SELECT id,name,type FROM categories WHERE type=? ORDER BY name":"SELECT id,name,type FROM categories ORDER BY type,name";
    sqlite3_prepare_v2(database,sql,-1,&st,0); if(type[0]) sqlite3_bind_text(st,1,type,-1,SQLITE_TRANSIENT);
    char out[RESPONSE_MAX]; size_t at=0; append(out,sizeof out,&at,"{\"categories\":["); bool first=true;
    while(sqlite3_step(st)==SQLITE_ROW) { char name[256]; escape_json(name,sizeof name,(const char*)sqlite3_column_text(st,1)); append(out,sizeof out,&at,"%s{\"id\":%d,\"name\":\"%s\",\"type\":\"%s\"}",first?"":",",sqlite3_column_int(st,0),name,sqlite3_column_text(st,2)); first=false; }
    sqlite3_finalize(st); append(out,sizeof out,&at,"]}"); json(s,200,out);
}
static void add_category(socket_t s, const Request *r) {
    char name[100],type[16]; if(!json_text(r->body,"name",name,sizeof name)||!json_text(r->body,"type",type,sizeof type)||!name[0]||(strcmp(type,"income")&&strcmp(type,"expense"))){error(s,400,"name and valid type are required");return;}
    sqlite3_stmt *st; sqlite3_prepare_v2(database,"INSERT INTO categories(name,type) VALUES(?,?)",-1,&st,0); sqlite3_bind_text(st,1,name,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,type,-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)!=SQLITE_DONE){sqlite3_finalize(st);error(s,400,"category already exists");return;} int id=(int)sqlite3_last_insert_rowid(database);sqlite3_finalize(st);char escaped[256],out[330];escape_json(escaped,sizeof escaped,name);snprintf(out,sizeof out,"{\"id\":%d,\"name\":\"%s\",\"type\":\"%s\"}",id,escaped,type);json(s,201,out);
}
static void transactions(socket_t s, const Request *r) {
    char month[16],type[16]; query(r,"month",month,sizeof month);query(r,"type",type,sizeof type);
    if((month[0]&&!month_ok(month))||(type[0]&&strcmp(type,"income")&&strcmp(type,"expense"))){error(s,400,"invalid filter");return;}
    const char *sql="SELECT t.id,t.record_date,t.type,c.id,c.name,t.amount_cents,t.note FROM transactions t JOIN categories c ON c.id=t.category_id WHERE (?='' OR substr(t.record_date,1,7)=?) AND (?='' OR t.type=?) ORDER BY t.record_date DESC,t.id DESC LIMIT 250"; sqlite3_stmt *st;sqlite3_prepare_v2(database,sql,-1,&st,0);for(int i=1;i<=4;i++)sqlite3_bind_text(st,i,i<=2?month:type,-1,SQLITE_TRANSIENT);
    char out[RESPONSE_MAX];size_t at=0;append(out,sizeof out,&at,"{\"transactions\":[");bool first=true;while(sqlite3_step(st)==SQLITE_ROW){char category[256],note[512];escape_json(category,sizeof category,(const char*)sqlite3_column_text(st,4));escape_json(note,sizeof note,(const char*)sqlite3_column_text(st,6));append(out,sizeof out,&at,"%s{\"id\":%d,\"date\":\"%s\",\"type\":\"%s\",\"categoryId\":%d,\"category\":\"%s\",\"amount\":%.2f,\"note\":\"%s\"}",first?"":",",sqlite3_column_int(st,0),sqlite3_column_text(st,1),sqlite3_column_text(st,2),sqlite3_column_int(st,3),category,sqlite3_column_int(st,5)/100.0,note);first=false;}sqlite3_finalize(st);append(out,sizeof out,&at,"]}");json(s,200,out);
}
static void current_balance(socket_t s) {
    sqlite3_stmt *st = NULL;
    const char *sql =
        "SELECT b.amount_cents+COALESCE(SUM(CASE WHEN t.type='income' THEN t.amount_cents ELSE -t.amount_cents END),0) "
        "FROM balance_state b LEFT JOIN transactions t ON t.id>b.through_transaction_id WHERE b.id=1";
    if (sqlite3_prepare_v2(database, sql, -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        error(s, 500, "Could not calculate current balance.");
        return;
    }
    long long cents = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    char body[96];
    snprintf(body, sizeof body, "{\"availableBalance\":%.2f}", cents / 100.0);
    json(s, 200, body);
}
static void set_current_balance(socket_t s, const Request *r) {
    int64_t amount_cents = 0;
    if (!json_integer(r->body, "amountCents", &amount_cents) ||
        amount_cents < 0 || amount_cents > INT64_C(1000000000)) {
        error(s, 400, "amountCents must be an integer from 0 to 1000000000.");
        return;
    }
    sqlite3_stmt *st = NULL;
    const char *sql =
        "UPDATE balance_state SET amount_cents=?,through_transaction_id="
        "(SELECT COALESCE(MAX(id),0) FROM transactions) WHERE id=1";
    if (sqlite3_prepare_v2(database, sql, -1, &st, NULL) != SQLITE_OK) {
        error(s, 500, "Could not prepare balance update.");
        return;
    }
    sqlite3_bind_int64(st, 1, amount_cents);
    int ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(database) == 1;
    sqlite3_finalize(st);
    if (!ok) {
        error(s, 500, "Could not save current balance.");
        return;
    }
    current_balance(s);
}
static void add_transaction(socket_t s, const Request *r) {
    char date[16], type[16], note[500];
    double category_id = 0;
    int64_t amount_cents = 0;
    if (!json_text(r->body, "date", date, sizeof date) ||
        !json_text(r->body, "type", type, sizeof type) ||
        !json_number(r->body, "categoryId", &category_id) ||
        !json_integer(r->body, "amountCents", &amount_cents) ||
        !date_ok(date) || (strcmp(type, "income") && strcmp(type, "expense")) ||
        category_id < 1 || amount_cents <= 0 || amount_cents > INT64_C(1000000000)) {
        error(s, 400, "invalid transaction; amountCents must be integer cents");
        return;
    }
    if (!json_text(r->body, "note", note, sizeof note)) note[0] = 0;
    sqlite3_stmt *st = NULL;
    const char *sql =
        "INSERT INTO transactions(id,record_date,type,category_id,amount_cents,note) "
        "SELECT MAX(COALESCE((SELECT MAX(id) FROM transactions),0),through_transaction_id)+1,"
        "?,?,?,?,? FROM balance_state WHERE id=1 AND "
        "EXISTS(SELECT 1 FROM categories WHERE id=? AND type=?)";
    if (sqlite3_prepare_v2(database, sql, -1, &st, NULL) != SQLITE_OK) {
        error(s, 500, "could not prepare transaction");
        return;
    }
    sqlite3_bind_text(st, 1, date, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, (int)category_id);
    sqlite3_bind_int64(st, 4, amount_cents);
    sqlite3_bind_text(st, 5, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, (int)category_id);
    sqlite3_bind_text(st, 7, type, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(database) != 1) {
        sqlite3_finalize(st);
        error(s, 400, "category type does not match");
        return;
    }
    int id = (int)sqlite3_last_insert_rowid(database);
    sqlite3_finalize(st);
    char out[64];
    snprintf(out, sizeof out, "{\"id\":%d}", id);
    json(s, 201, out);
}

static void update_transaction(socket_t s, const Request *r) {
    char *end;
    long id = strtol(r->path + 18, &end, 10);
    char date[16], type[16], note[500];
    double category_id = 0;
    int64_t amount_cents = 0;
    if (id < 1 || *end ||
        !json_text(r->body, "date", date, sizeof date) ||
        !json_text(r->body, "type", type, sizeof type) ||
        !json_number(r->body, "categoryId", &category_id) ||
        !json_integer(r->body, "amountCents", &amount_cents) ||
        !date_ok(date) || (strcmp(type, "income") && strcmp(type, "expense")) ||
        category_id < 1 || amount_cents <= 0 || amount_cents > INT64_C(1000000000)) {
        error(s, 400, "invalid transaction; amountCents must be integer cents");
        return;
    }
    if (!json_text(r->body, "note", note, sizeof note)) note[0] = 0;
    sqlite3_stmt *st = NULL;
    const char *sql =
        "UPDATE transactions SET record_date=?,type=?,category_id=?,amount_cents=?,note=? "
        "WHERE id=? AND EXISTS(SELECT 1 FROM categories WHERE id=? AND type=?)";
    if (sqlite3_prepare_v2(database, sql, -1, &st, NULL) != SQLITE_OK) {
        error(s, 500, "could not prepare transaction update");
        return;
    }
    sqlite3_bind_text(st, 1, date, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, (int)category_id);
    sqlite3_bind_int64(st, 4, amount_cents);
    sqlite3_bind_text(st, 5, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, (int)id);
    sqlite3_bind_int(st, 7, (int)category_id);
    sqlite3_bind_text(st, 8, type, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        error(s, 500, "could not update transaction");
        return;
    }
    int changed = sqlite3_changes(database);
    sqlite3_finalize(st);
    if (!changed) {
        error(s, 404, "transaction not found or category mismatch");
        return;
    }
    json(s, 200, "{\"ok\":true}");
}
static void export_csv(socket_t s,const Request *r){char month[16];query(r,"month",month,sizeof month);if(!month_ok(month)){error(s,400,"valid month required");return;}sqlite3_stmt *st;sqlite3_prepare_v2(database,"SELECT t.record_date,t.type,c.name,t.amount_cents,t.note FROM transactions t JOIN categories c ON c.id=t.category_id WHERE substr(t.record_date,1,7)=? ORDER BY t.record_date,t.id",-1,&st,0);sqlite3_bind_text(st,1,month,-1,SQLITE_TRANSIENT);char out[RESPONSE_MAX];size_t at=0;append(out,sizeof out,&at,"date,type,category,amount,note\n");while(sqlite3_step(st)==SQLITE_ROW){const char *date=(const char*)sqlite3_column_text(st,0);const char *type=(const char*)sqlite3_column_text(st,1);const char *category=(const char*)sqlite3_column_text(st,2);const char *note=(const char*)sqlite3_column_text(st,4);csv_field(out,sizeof out,&at,date);append(out,sizeof out,&at,",%s,",type);csv_field(out,sizeof out,&at,category);append(out,sizeof out,&at,",%.2f,",sqlite3_column_int(st,3)/100.0);csv_field(out,sizeof out,&at,note);append(out,sizeof out,&at,"\n");}sqlite3_finalize(st);reply(s,200,"text/csv",out,at);}
static void remove_transaction(socket_t s,const char *path){char *end;long id=strtol(path+18,&end,10);if(id<1||*end){error(s,400,"invalid transaction id");return;}sqlite3_stmt *st;sqlite3_prepare_v2(database,"DELETE FROM transactions WHERE id=?",-1,&st,0);sqlite3_bind_int(st,1,(int)id);sqlite3_step(st);int changed=sqlite3_changes(database);sqlite3_finalize(st);if(!changed){error(s,404,"transaction not found");return;}reply(s,204,"application/json",0,0);}
static void dashboard(socket_t s,const Request *r){char month[16];query(r,"month",month,sizeof month);if(!month_ok(month)){error(s,400,"valid month required");return;}long income=0,expense=0,budget=0;sqlite3_stmt *st;sqlite3_prepare_v2(database,"SELECT type,SUM(amount_cents) FROM transactions WHERE substr(record_date,1,7)=? GROUP BY type",-1,&st,0);sqlite3_bind_text(st,1,month,-1,SQLITE_TRANSIENT);while(sqlite3_step(st)==SQLITE_ROW){if(!strcmp((const char*)sqlite3_column_text(st,0),"income"))income=sqlite3_column_int(st,1);else expense=sqlite3_column_int(st,1);}sqlite3_finalize(st);sqlite3_prepare_v2(database,"SELECT COALESCE(SUM(amount_cents),0) FROM budgets WHERE month=?",-1,&st,0);sqlite3_bind_text(st,1,month,-1,SQLITE_TRANSIENT);if(sqlite3_step(st)==SQLITE_ROW)budget=sqlite3_column_int(st,0);sqlite3_finalize(st);sqlite3_int64 available=0;const char *balance_sql="SELECT b.amount_cents+COALESCE(SUM(CASE WHEN t.type='income' THEN t.amount_cents ELSE -t.amount_cents END),0) FROM balance_state b LEFT JOIN transactions t ON t.id>b.through_transaction_id WHERE b.id=1";if(sqlite3_prepare_v2(database,balance_sql,-1,&st,0)!=SQLITE_OK||sqlite3_step(st)!=SQLITE_ROW){sqlite3_finalize(st);error(s,500,"Could not calculate current balance.");return;}available=sqlite3_column_int64(st,0);sqlite3_finalize(st);const char *sql="SELECT c.id,c.name,SUM(t.amount_cents) FROM transactions t JOIN categories c ON c.id=t.category_id WHERE substr(t.record_date,1,7)=? AND t.type='expense' GROUP BY c.id,c.name ORDER BY 3 DESC";sqlite3_prepare_v2(database,sql,-1,&st,0);sqlite3_bind_text(st,1,month,-1,SQLITE_TRANSIENT);char out[RESPONSE_MAX];size_t at=0;append(out,sizeof out,&at,"{\"income\":%.2f,\"expense\":%.2f,\"balance\":%.2f,\"availableBalance\":%.2f,\"budget\":%.2f,\"categories\":[",income/100.,expense/100.,(income-expense)/100.,available/100.,budget/100.);bool first=true;while(sqlite3_step(st)==SQLITE_ROW){char n[256];escape_json(n,sizeof n,(const char*)sqlite3_column_text(st,1));append(out,sizeof out,&at,"%s{\"id\":%d,\"name\":\"%s\",\"amount\":%.2f}",first?"":",",sqlite3_column_int(st,0),n,sqlite3_column_int(st,2)/100.);first=false;}sqlite3_finalize(st);append(out,sizeof out,&at,"]}");json(s,200,out);}
static void budgets(socket_t s,const Request *r){char month[16];query(r,"month",month,sizeof month);if(!month_ok(month)){error(s,400,"valid month required");return;}sqlite3_stmt *st;const char *sql="SELECT c.id,c.name,COALESCE(b.amount_cents,0) FROM categories c LEFT JOIN budgets b ON b.category_id=c.id AND b.month=? WHERE c.type='expense' ORDER BY c.name";sqlite3_prepare_v2(database,sql,-1,&st,0);sqlite3_bind_text(st,1,month,-1,SQLITE_TRANSIENT);char out[RESPONSE_MAX];size_t at=0;append(out,sizeof out,&at,"{\"budgets\":[");bool first=true;while(sqlite3_step(st)==SQLITE_ROW){char n[256];escape_json(n,sizeof n,(const char*)sqlite3_column_text(st,1));append(out,sizeof out,&at,"%s{\"categoryId\":%d,\"category\":\"%s\",\"amount\":%.2f}",first?"":",",sqlite3_column_int(st,0),n,sqlite3_column_int(st,2)/100.);first=false;}sqlite3_finalize(st);append(out,sizeof out,&at,"]}");json(s,200,out);}
static void save_budget(socket_t s, const Request *r) {
    char month[16];
    double category_id = 0;
    int64_t amount_cents = 0;
    if (!json_text(r->body, "month", month, sizeof month) ||
        !json_number(r->body, "categoryId", &category_id) ||
        !json_integer(r->body, "amountCents", &amount_cents) ||
        !month_ok(month) || category_id < 1 || amount_cents < 0 ||
        amount_cents > INT64_C(1000000000)) {
        error(s, 400, "invalid budget; amountCents must be integer cents");
        return;
    }
    sqlite3_stmt *st = NULL;
    const char *sql =
        "INSERT INTO budgets(month,category_id,amount_cents) VALUES(?,?,?) "
        "ON CONFLICT(month,category_id) DO UPDATE SET amount_cents=excluded.amount_cents";
    if (sqlite3_prepare_v2(database, sql, -1, &st, NULL) != SQLITE_OK) {
        error(s, 500, "could not prepare budget");
        return;
    }
    sqlite3_bind_text(st, 1, month, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, (int)category_id);
    sqlite3_bind_int64(st, 3, amount_cents);
    int ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) {
        error(s, 500, "could not save budget");
        return;
    }
    json(s, 200, "{\"ok\":true}");
}

static void static_file(socket_t s,const char *path){const char *file=!strcmp(path,"/")?"web/index.html":!strcmp(path,"/app.css")?"web/app.css":!strcmp(path,"/app.js")?"web/app.js":0;if(!file){error(s,404,"route not found");return;}FILE *f=fopen(file,"rb");if(!f){error(s,404,"web asset not found; run from project directory");return;}char data[RESPONSE_MAX];size_t n=fread(data,1,sizeof data,f);fclose(f);reply(s,200,strstr(file,".css")?"text/css":strstr(file,".js")?"application/javascript":"text/html",data,n);}
static void route(socket_t s,const Request *r) {
    if (!strncmp(r->path, "/api/", 5)) {
        if (!strcmp(r->path, "/api/auth/status") && !strcmp(r->method, "GET")) {
            auth_status(s);
            return;
        }
        if (!strcmp(r->path, "/api/auth/setup") && !strcmp(r->method, "POST")) {
            auth_setup(s, r);
            return;
        }
        if (!strcmp(r->path, "/api/auth/login") && !strcmp(r->method, "POST")) {
            auth_login(s, r);
            return;
        }
        if (!strcmp(r->path, "/api/auth/recover") && !strcmp(r->method, "POST")) {
            auth_recover(s, r);
            return;
        }
        if (!session_valid(r)) {
            error(s, 401, "Authentication required.");
            return;
        }
        if (!strcmp(r->path, "/api/auth/logout") && !strcmp(r->method, "POST")) {
            auth_logout(s);
            return;
        }
        if (!strcmp(r->path, "/api/categories")) {
            if (!strcmp(r->method, "GET")) categories(s, r);
            else if (!strcmp(r->method, "POST")) add_category(s, r);
            else error(s, 400, "method not allowed");
            return;
        }
        if (!strcmp(r->path, "/api/transactions")) {
            if (!strcmp(r->method, "GET")) transactions(s, r);
            else if (!strcmp(r->method, "POST")) add_transaction(s, r);
            else error(s, 400, "method not allowed");
            return;
        }
        if (!strncmp(r->path, "/api/transactions/", 18)) {
            if (!strcmp(r->method, "DELETE")) remove_transaction(s, r->path);
            else if (!strcmp(r->method, "PUT")) update_transaction(s, r);
            else error(s, 400, "method not allowed");
            return;
        }
        if (!strcmp(r->path, "/api/dashboard") && !strcmp(r->method, "GET")) {
            dashboard(s, r);
            return;
        }
        if (!strcmp(r->path, "/api/balance")) {
            if (!strcmp(r->method, "PUT")) set_current_balance(s, r);
            else error(s, 400, "method not allowed");
            return;
        }
        if (!strcmp(r->path, "/api/budgets")) {
            if (!strcmp(r->method, "GET")) budgets(s, r);
            else if (!strcmp(r->method, "PUT")) save_budget(s, r);
            else error(s, 400, "method not allowed");
            return;
        }
        if (!strcmp(r->path, "/api/export") && !strcmp(r->method, "GET")) {
            export_csv(s, r);
            return;
        }
        error(s, 404, "route not found");
        return;
    }
    static_file(s, r->path);
}
static void handle(socket_t s) {
    char raw[REQUEST_MAX + 1];
    int n = recv(s, raw, REQUEST_MAX, 0);
    if (n <= 0) return;
    raw[n] = 0;
    char *end = strstr(raw, "\r\n"), *body = strstr(raw, "\r\n\r\n");
    if (!end || !body) { error(s, 400, "malformed request"); return; }
    char *length_header = strstr(raw, "Content-Length:");
    long content_length = length_header ? strtol(length_header + 15, 0, 10) : 0;
    size_t header_length = (size_t)(body + 4 - raw);
    while (n < (int)(header_length + content_length) && n < REQUEST_MAX) {
        int received = recv(s, raw + n, REQUEST_MAX - n, 0);
        if (received <= 0) { error(s, 400, "incomplete request body"); return; }
        n += received;
        raw[n] = 0;
    }
    if (n < (int)(header_length + content_length)) {
        error(s, 400, "request body too large");
        return;
    }
    Request r = {0};
    char target[520] = {0};
    if (sscanf(raw, "%7s %519s", r.method, target) != 2) {
        error(s, 400, "invalid request");
        return;
    }
    char *question = strchr(target, '?');
    if (question) {
        *question = 0;
        snprintf(r.query, sizeof r.query, "%s", question + 1);
    }
    snprintf(r.path, sizeof r.path, "%s", target);
    r.body = body + 4;
    char host[64] = {0}, origin[128] = {0}, content_type[128] = {0}, cookie[256] = {0};
    if (!request_header(raw, body, "Host", host, sizeof host) || !local_host(host)) {
        error(s, 400, "invalid host");
        return;
    }
    bool mutating = !strcmp(r.method, "POST") || !strcmp(r.method, "PUT") ||
                    !strcmp(r.method, "DELETE");
    if (mutating && !request_header(raw, body, "Origin", origin, sizeof origin)) {
        error(s, 403, "origin required");
        return;
    }
    if (mutating && !trusted_origin(origin, host)) {
        error(s, 403, "untrusted origin");
        return;
    }
    if ((!strcmp(r.method, "POST") || !strcmp(r.method, "PUT")) &&
        (!request_header(raw, body, "Content-Type", content_type, sizeof content_type) ||
         !json_content_type(content_type))) {
        error(s, 415, "application/json required");
        return;
    }
    if (request_header(raw, body, "Cookie", cookie, sizeof cookie))
        request_session(cookie, r.session, sizeof r.session);
    route(s, &r);
}
int main(void){
#ifdef _WIN32
WSADATA w; if(WSAStartup(MAKEWORD(2,2),&w)){return 1;}
#endif
make_dir("data");
socket_t server=socket(AF_INET,SOCK_STREAM,0);if(server==INVALID_SOCKET){fprintf(stderr,"Could not create local server socket\n");return 1;}
#ifdef _WIN32
BOOL exclusive=TRUE;if(setsockopt(server,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char*)&exclusive,sizeof exclusive)==SOCKET_ERROR){fprintf(stderr,"Could not secure exclusive local port\n");CLOSE_SOCKET(server);return 1;}
#else
int reuse=1;if(setsockopt(server,SOL_SOCKET,SO_REUSEADDR,(const char*)&reuse,sizeof reuse)==SOCKET_ERROR){fprintf(stderr,"Could not configure local port\n");CLOSE_SOCKET(server);return 1;}
#endif
struct sockaddr_in addr={0};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=htons(PORT);if(bind(server,(struct sockaddr*)&addr,sizeof addr)==SOCKET_ERROR||listen(server,16)==SOCKET_ERROR){fprintf(stderr,"Port %d is unavailable\n",PORT);CLOSE_SOCKET(server);return 1;}printf("Open http://127.0.0.1:%d\n",PORT);for(;;){socket_t client=accept(server,0,0);if(client!=INVALID_SOCKET){handle(client);CLOSE_SOCKET(client);}}}
