/* Windows desktop edition of Campus Finance. C17 + Win32 + SQLite. */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <sqlite3.h>
#include "security.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <math.h>

enum { ID_TYPE=101, ID_CATEGORY, ID_TIME, ID_AMOUNT, ID_NOTE, ID_ADD, ID_UPDATE,
       ID_DELETE, ID_REFRESH, ID_EXPORT, ID_BUDGET, ID_SAVE_BUDGET, ID_LIST,
       ID_MONTH, ID_HISTORY, ID_COMPARISON, ID_SET_BALANCE };

static sqlite3 *db;
static HWND type_box, category_box, time_edit, amount_edit, note_edit, budget_edit, month_edit, list_view, comparison_view, summary_text, available_text, balance_edit;
static int editing_id = 0;
static int show_all_history = 0;
static HWND secret_edit;
static wchar_t secret_output[512], secret_label[256];
static int secret_completed;
static void message(const wchar_t *text);

static LRESULT CALLBACK secret_prompt_proc(HWND window, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_CREATE) {
        CreateWindowW(L"STATIC", secret_label, WS_CHILD|WS_VISIBLE, 18, 16, 400, 38,
                      window, NULL, NULL, NULL);
        secret_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD|WS_VISIBLE|ES_PASSWORD|ES_AUTOHSCROLL, 18, 58, 400, 28,
            window, (HMENU)101, NULL, NULL);
        CreateWindowW(L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                      242, 102, 82, 30, window, (HMENU)IDOK, NULL, NULL);
        CreateWindowW(L"BUTTON", L"取消", WS_CHILD|WS_VISIBLE,
                      336, 102, 82, 30, window, (HMENU)IDCANCEL, NULL, NULL);
        SetFocus(secret_edit);
        return 0;
    }
    if (msg == WM_COMMAND && (LOWORD(w) == IDOK || LOWORD(w) == IDCANCEL)) {
        secret_completed = LOWORD(w) == IDOK;
        if (secret_completed) GetWindowTextW(secret_edit, secret_output, 512);
        DestroyWindow(window);
        return 0;
    }
    if (msg == WM_CLOSE) {
        secret_completed = 0;
        DestroyWindow(window);
        return 0;
    }
    return DefWindowProcW(window, msg, w, l);
}

static int prompt_secret(const wchar_t *title, const wchar_t *label, wchar_t *output, size_t capacity) {
    static int registered;
    if (!registered) {
        WNDCLASSW wc = {0};
        wc.lpfnWndProc = secret_prompt_proc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"CampusFinanceSecretPrompt";
        if (!RegisterClassW(&wc)) return 0;
        registered = 1;
    }
    wcsncpy(secret_label, label, 255);
    secret_label[255] = 0;
    secret_output[0] = 0;
    secret_completed = 0;
    HWND window = CreateWindowExW(WS_EX_DLGMODALFRAME|WS_EX_TOPMOST,
        L"CampusFinanceSecretPrompt", title, WS_CAPTION|WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 455, 184, NULL, NULL,
        GetModuleHandleW(NULL), NULL);
    if (!window) return 0;
    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
    MSG msg;
    while (IsWindow(window)) {
        int result = GetMessageW(&msg, NULL, 0, 0);
        if (result <= 0) break;
        if (!IsDialogMessageW(window, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (secret_completed) {
        wcsncpy(output, secret_output, capacity - 1);
        output[capacity - 1] = 0;
    }
    SecureZeroMemory(secret_output, sizeof secret_output);
    return secret_completed;
}

static int secret_to_utf8(const wchar_t *secret, char *out, int capacity) {
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, secret, -1, out,
                               capacity, NULL, NULL) > 0;
}

static int authenticate_database(void) {
    char credential[1024] = {0}, recovery[65] = {0};
    char error[256] = {0};
    if (security_is_initialized()) {
        for (;;) {
            wchar_t entered[512];
            if (!prompt_secret(L"校园财务台登录", L"输入登录密码；忘记密码时可输入恢复密钥。", entered, 512))
                return 0;
            int converted = secret_to_utf8(entered, credential, sizeof credential);
            SecureZeroMemory(entered, sizeof entered);
            bool used_recovery = false;
            if (converted && security_unlock_database(credential, &db, &used_recovery,
                                                       error, sizeof error)) {
                if (used_recovery) {
                    char recovery_credential[1024];
                    char new_recovery[65] = {0};
                    snprintf(recovery_credential, sizeof recovery_credential, "%s", credential);
                    wchar_t new_password[512], confirm_password[512];
                    if (!prompt_secret(L"重设登录密码", L"已用恢复密钥解锁，请设置新密码（至少 12 个字符）。",
                                       new_password, 512) ||
                        !prompt_secret(L"确认新密码", L"请再次输入新密码。", confirm_password, 512) ||
                        wcscmp(new_password, confirm_password) != 0 ||
                        !secret_to_utf8(new_password, credential, sizeof credential) ||
                        !security_reset_password(recovery_credential, credential,
                                                 new_recovery, sizeof new_recovery,
                                                 error, sizeof error)) {
                        security_close_database(db);
                        db = NULL;
                        message(L"密码重设失败或两次输入不一致。请重新登录并重试。");
                        SecureZeroMemory(new_password, sizeof new_password);
                        SecureZeroMemory(confirm_password, sizeof confirm_password);
                        SecureZeroMemory(recovery_credential, sizeof recovery_credential);
                        SecureZeroMemory(new_recovery, sizeof new_recovery);
                        continue;
                    }
                    wchar_t recovery_wide[128], notice[256];
                    MultiByteToWideChar(CP_UTF8, 0, new_recovery, -1, recovery_wide, 128);
                    swprintf(notice, 256,
                        L"旧恢复密钥已撤销。请保存新的恢复密钥；此密钥只显示这一次：\n\n%ls",
                        recovery_wide);
                    MessageBoxW(NULL, notice, L"保存新的恢复密钥", MB_OK|MB_ICONWARNING);
                    SecureZeroMemory(new_password, sizeof new_password);
                    SecureZeroMemory(confirm_password, sizeof confirm_password);
                    SecureZeroMemory(recovery_credential, sizeof recovery_credential);
                    SecureZeroMemory(new_recovery, sizeof new_recovery);
                }
                SecureZeroMemory(credential, sizeof credential);
                return 1;
            }
            message(L"密码或恢复密钥不正确。");
            SecureZeroMemory(credential, sizeof credential);
        }
    }
    for (;;) {
        wchar_t password[512], confirm[512];
        if (!prompt_secret(L"创建账本密码", L"设置登录密码（至少 12 个字符）。", password, 512))
            return 0;
        if (!prompt_secret(L"确认账本密码", L"请再次输入登录密码。", confirm, 512)) {
            SecureZeroMemory(password, sizeof password);
            return 0;
        }
        if (wcscmp(password, confirm) != 0 || !secret_to_utf8(password, credential, sizeof credential)) {
            message(L"两次密码不一致。");
            SecureZeroMemory(password, sizeof password);
            SecureZeroMemory(confirm, sizeof confirm);
            continue;
        }
        SecureZeroMemory(password, sizeof password);
        SecureZeroMemory(confirm, sizeof confirm);
        if (security_create_database(credential, recovery, sizeof recovery, &db,
                                     error, sizeof error)) {
            wchar_t notice[256];
            wchar_t recovery_wide[128];
            MultiByteToWideChar(CP_UTF8, 0, recovery, -1, recovery_wide, 128);
            swprintf(notice, 256, L"请保存恢复密钥；这是忘记密码时找回账本的唯一方式：\n\n%ls\n\n此密钥只显示这一次，请妥善保管。", recovery_wide);
            MessageBoxW(NULL, notice, L"保存账本恢复密钥", MB_OK|MB_ICONWARNING);
            SecureZeroMemory(credential, sizeof credential);
            SecureZeroMemory(recovery, sizeof recovery);
            return 1;
        }
        wchar_t failure[320];
        MultiByteToWideChar(CP_UTF8, 0, error, -1, failure, 320);
        MessageBoxW(NULL, failure, L"无法创建加密账本", MB_OK|MB_ICONERROR);
        SecureZeroMemory(credential, sizeof credential);
        return 0;
    }
}

static void wide_to_utf8(const wchar_t *wide, char *utf8, int size) {
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, size, NULL, NULL);
}
static void text_of(HWND control, wchar_t *text, int length) { GetWindowTextW(control, text, length); }
static void message(const wchar_t *text) { MessageBoxW(NULL, text, L"校园财务台", MB_OK | MB_ICONINFORMATION); }
static void now_text(wchar_t *out, int length) {
    time_t current=time(NULL); struct tm local; localtime_s(&local, &current);
    wcsftime(out, length, L"%Y-%m-%d %H:%M", &local);
}
static void selected_month(char *out, int capacity) {
    wchar_t value[16]; text_of(month_edit, value, 16); wide_to_utf8(value, out, capacity); out[7]=0;
}
static int selected_category(void) {
    int index=(int)SendMessageW(category_box, CB_GETCURSEL, 0, 0);
    return index==CB_ERR ? 0 : (int)SendMessageW(category_box, CB_GETITEMDATA, index, 0);
}
static const char *selected_type(void) { return SendMessageW(type_box, CB_GETCURSEL, 0, 0)==1 ? "income" : "expense"; }
static void exec_sql(const char *sql) { sqlite3_exec(db, sql, NULL, NULL, NULL); }

static int open_database(void) {
    CreateDirectoryW(L"data", NULL);
    if (!authenticate_database()) return 0;
    exec_sql("PRAGMA foreign_keys=ON;");
    exec_sql("CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY,name TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN('income','expense')),UNIQUE(name,type));");
    exec_sql("CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY,record_date TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN('income','expense')),category_id INTEGER NOT NULL REFERENCES categories(id),amount_cents INTEGER NOT NULL CHECK(amount_cents>0),note TEXT NOT NULL DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);");
    exec_sql("CREATE TABLE IF NOT EXISTS budgets(month TEXT NOT NULL,category_id INTEGER NOT NULL REFERENCES categories(id),amount_cents INTEGER NOT NULL CHECK(amount_cents>=0),PRIMARY KEY(month,category_id));");
    exec_sql("CREATE TABLE IF NOT EXISTS balance_state(id INTEGER PRIMARY KEY CHECK(id=1),amount_cents INTEGER NOT NULL CHECK(amount_cents>=0),through_transaction_id INTEGER NOT NULL DEFAULT 0);");
    exec_sql("INSERT OR IGNORE INTO balance_state(id,amount_cents,through_transaction_id) VALUES(1,0,0);");
    /* Makes the existing web database compatible without losing old entries. */
    exec_sql("ALTER TABLE transactions ADD COLUMN record_time TEXT;");
    exec_sql("UPDATE transactions SET record_time=record_date||' 00:00' WHERE record_time IS NULL;");
    exec_sql("INSERT OR IGNORE INTO categories(name,type) VALUES('生活费','income'),('奖学金','income'),('兼职','income'),('退款','income'),('餐饮','expense'),('交通','expense'),('学习','expense'),('住宿','expense'),('日用品','expense'),('娱乐','expense'),('医疗','expense'),('通讯','expense');");
    return 1;
}

static void load_categories(void) {
    const char *type=selected_type(); sqlite3_stmt *st=NULL;
    SendMessageW(category_box, CB_RESETCONTENT, 0, 0);
    sqlite3_prepare_v2(db, "SELECT id,name FROM categories WHERE type=? ORDER BY name", -1, &st, NULL);
    sqlite3_bind_text(st, 1, type, -1, SQLITE_STATIC);
    while (sqlite3_step(st)==SQLITE_ROW) {
        const char *name=(const char*)sqlite3_column_text(st,1); wchar_t wide[128]; MultiByteToWideChar(CP_UTF8,0,name,-1,wide,128);
        int index=(int)SendMessageW(category_box,CB_ADDSTRING,0,(LPARAM)wide);
        SendMessageW(category_box,CB_SETITEMDATA,index,sqlite3_column_int(st,0));
    }
    sqlite3_finalize(st); SendMessageW(category_box, CB_SETCURSEL, 0, 0);
}

static void refresh_summary(void) {
    char month[16]; selected_month(month,sizeof month); sqlite3_stmt *st=NULL; long income=0,expense=0,budget=0;
    sqlite3_prepare_v2(db,"SELECT type,COALESCE(SUM(amount_cents),0) FROM transactions WHERE substr(record_time,1,7)=? GROUP BY type",-1,&st,NULL); sqlite3_bind_text(st,1,month,-1,SQLITE_TRANSIENT);
    while(sqlite3_step(st)==SQLITE_ROW) { if(!strcmp((const char*)sqlite3_column_text(st,0),"income")) income=sqlite3_column_int(st,1); else expense=sqlite3_column_int(st,1); } sqlite3_finalize(st);
    sqlite3_prepare_v2(db,"SELECT COALESCE(SUM(amount_cents),0) FROM budgets WHERE month=?",-1,&st,NULL); sqlite3_bind_text(st,1,month,-1,SQLITE_TRANSIENT); if(sqlite3_step(st)==SQLITE_ROW) budget=sqlite3_column_int(st,0); sqlite3_finalize(st);
    sqlite3_int64 available=0;
    if(sqlite3_prepare_v2(db,"SELECT b.amount_cents+COALESCE(SUM(CASE WHEN t.type='income' THEN t.amount_cents ELSE -t.amount_cents END),0) FROM balance_state b LEFT JOIN transactions t ON t.id>b.through_transaction_id WHERE b.id=1",-1,&st,NULL)!=SQLITE_OK||sqlite3_step(st)!=SQLITE_ROW){sqlite3_finalize(st);message(L"无法读取目前可支配金额。");return;}
    available=sqlite3_column_int64(st,0);sqlite3_finalize(st);
    wchar_t display[256],amount[64];swprintf(display,256,L"目前可支配金额：¥%.2f",available/100.0);SetWindowTextW(available_text,display);swprintf(amount,64,L"%.2f",available/100.0);SetWindowTextW(balance_edit,amount);
    swprintf(display,256,L"本月收入：¥%.2f    本月支出：¥%.2f    结余：¥%.2f    分类预算合计：¥%.2f",income/100.0,expense/100.0,(income-expense)/100.0,budget/100.0); SetWindowTextW(summary_text,display);
}

static void set_current_balance(void) {
    wchar_t value[64];text_of(balance_edit,value,64);wchar_t *end=NULL;double amount=wcstod(value,&end);
    if(end==value||*end||!isfinite(amount)||amount<0||amount>10000000){message(L"请输入 0 到 10000000 之间的有效金额。");return;}
    sqlite3_stmt *st=NULL;
    const char *sql="UPDATE balance_state SET amount_cents=?,through_transaction_id=(SELECT COALESCE(MAX(id),0) FROM transactions) WHERE id=1";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)!=SQLITE_OK){message(L"无法准备余额保存操作。");return;}
    sqlite3_bind_int64(st,1,(sqlite3_int64)(amount*100+0.5));
    int ok=sqlite3_step(st)==SQLITE_DONE&&sqlite3_changes(db)==1;sqlite3_finalize(st);
    if(!ok){message(L"余额保存失败，请重试。");return;}
    refresh_summary();
}

static void refresh_comparison(void);
static void refresh_list(void) {
    char month[16]; selected_month(month,sizeof month); SendMessageW(list_view,LVM_DELETEALLITEMS,0,0);
    sqlite3_stmt *st=NULL; const char *sql=show_all_history?"SELECT t.id,t.record_time,t.type,c.name,t.amount_cents,t.note FROM transactions t JOIN categories c ON c.id=t.category_id ORDER BY t.record_time DESC,t.id DESC":"SELECT t.id,t.record_time,t.type,c.name,t.amount_cents,t.note FROM transactions t JOIN categories c ON c.id=t.category_id WHERE substr(t.record_time,1,7)=? ORDER BY t.record_time DESC,t.id DESC";
    sqlite3_prepare_v2(db,sql,-1,&st,NULL); if(!show_all_history)sqlite3_bind_text(st,1,month,-1,SQLITE_TRANSIENT); int row=0;
    while(sqlite3_step(st)==SQLITE_ROW) {
        wchar_t fields[5][256]; const char *values[4]={(const char*)sqlite3_column_text(st,1),(const char*)sqlite3_column_text(st,3),(const char*)sqlite3_column_text(st,5),NULL};
        MultiByteToWideChar(CP_UTF8,0,values[0],-1,fields[0],256); MultiByteToWideChar(CP_UTF8,0,!strcmp((const char*)sqlite3_column_text(st,2),"income")?"收入":"支出",-1,fields[1],256); MultiByteToWideChar(CP_UTF8,0,values[1],-1,fields[2],256); MultiByteToWideChar(CP_UTF8,0,values[2],-1,fields[4],256); swprintf(fields[3],256,L"¥%.2f",sqlite3_column_int(st,4)/100.0);
        LVITEMW item={0}; item.mask=LVIF_TEXT|LVIF_PARAM;item.iItem=row;item.pszText=fields[0];item.lParam=sqlite3_column_int(st,0); ListView_InsertItem(list_view,&item);
        for(int col=1;col<5;col++){LVITEMW sub={0};sub.mask=LVIF_TEXT;sub.iItem=row;sub.iSubItem=col;sub.pszText=fields[col];ListView_SetItem(list_view,&sub);} row++;
    }
    sqlite3_finalize(st); refresh_summary(); refresh_comparison();
}

static void refresh_comparison(void) {
    SendMessageW(comparison_view,LVM_DELETEALLITEMS,0,0); sqlite3_stmt *st=NULL;
    sqlite3_prepare_v2(db,"SELECT substr(record_time,1,7),COALESCE(SUM(CASE WHEN type='income' THEN amount_cents ELSE 0 END),0),COALESCE(SUM(CASE WHEN type='expense' THEN amount_cents ELSE 0 END),0) FROM transactions GROUP BY substr(record_time,1,7) ORDER BY 1 DESC LIMIT 24",-1,&st,NULL);
    int row=0; while(sqlite3_step(st)==SQLITE_ROW){wchar_t fields[4][64];MultiByteToWideChar(CP_UTF8,0,(const char*)sqlite3_column_text(st,0),-1,fields[0],64);long income=sqlite3_column_int(st,1),expense=sqlite3_column_int(st,2);swprintf(fields[1],64,L"¥%.0f",income/100.0);swprintf(fields[2],64,L"¥%.0f",expense/100.0);swprintf(fields[3],64,L"¥%.0f",(income-expense)/100.0);LVITEMW item={0};item.mask=LVIF_TEXT;item.iItem=row;item.pszText=fields[0];ListView_InsertItem(comparison_view,&item);for(int col=1;col<4;col++){LVITEMW sub={0};sub.mask=LVIF_TEXT;sub.iItem=row;sub.iSubItem=col;sub.pszText=fields[col];ListView_SetItem(comparison_view,&sub);}row++;}sqlite3_finalize(st);
}

static int ensure_category(void) {
    int id=selected_category(); if(id) return id;
    wchar_t name_w[100]; text_of(category_box,name_w,100); if(!name_w[0]) return 0; char name[300]; wide_to_utf8(name_w,name,sizeof name);
    sqlite3_stmt *st=NULL; sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO categories(name,type) VALUES(?,?)",-1,&st,NULL);sqlite3_bind_text(st,1,name,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,selected_type(),-1,SQLITE_STATIC);sqlite3_step(st);sqlite3_finalize(st);load_categories();
    sqlite3_prepare_v2(db,"SELECT id FROM categories WHERE name=? AND type=?",-1,&st,NULL);sqlite3_bind_text(st,1,name,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,selected_type(),-1,SQLITE_STATIC);id=sqlite3_step(st)==SQLITE_ROW?sqlite3_column_int(st,0):0;sqlite3_finalize(st);return id;
}

static void save_transaction(int update) {
    wchar_t moment_w[32],amount_w[32],note_w[300]; text_of(time_edit,moment_w,32);text_of(amount_edit,amount_w,32);text_of(note_edit,note_w,300);
    if(wcslen(moment_w)!=16 || moment_w[4]!=L'-' || moment_w[7]!=L'-' || moment_w[10]!=L' ' || moment_w[13]!=L':'){message(L"时间格式请使用 YYYY-MM-DD HH:MM。");return;}
    double amount=wcstod(amount_w,NULL); int category=ensure_category(); if(amount<=0||!category){message(L"请填写正确的金额和类别。");return;}
    char moment[40],note[900],date[16];wide_to_utf8(moment_w,moment,sizeof moment);wide_to_utf8(note_w,note,sizeof note);memcpy(date,moment,10);date[10]=0;
    const char *sql=update?"UPDATE transactions SET record_date=?,record_time=?,type=?,category_id=?,amount_cents=?,note=? WHERE id=?":"INSERT INTO transactions(id,record_date,record_time,type,category_id,amount_cents,note) SELECT MAX(COALESCE((SELECT MAX(id) FROM transactions),0),through_transaction_id)+1,?,?,?,?,?,? FROM balance_state WHERE id=1";
    sqlite3_stmt *st=NULL;sqlite3_prepare_v2(db,sql,-1,&st,NULL);sqlite3_bind_text(st,1,date,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,moment,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,selected_type(),-1,SQLITE_STATIC);sqlite3_bind_int(st,4,category);sqlite3_bind_int(st,5,(int)(amount*100+.5));sqlite3_bind_text(st,6,note,-1,SQLITE_TRANSIENT);if(update)sqlite3_bind_int(st,7,editing_id);
    int ok=sqlite3_step(st)==SQLITE_DONE;sqlite3_finalize(st);if(!ok){message(L"保存失败。请重试。");return;} editing_id=0;SetWindowTextW(amount_edit,L"");SetWindowTextW(note_edit,L"");refresh_list();
}

static void edit_selected(void) {
    int row=ListView_GetNextItem(list_view,-1,LVNI_SELECTED);if(row<0){message(L"请先在表格中选择一笔账目。");return;}LVITEMW item={.mask=LVIF_PARAM,.iItem=row};ListView_GetItem(list_view,&item);editing_id=(int)item.lParam;
    sqlite3_stmt *st=NULL;sqlite3_prepare_v2(db,"SELECT record_time,type,category_id,amount_cents,note FROM transactions WHERE id=?",-1,&st,NULL);sqlite3_bind_int(st,1,editing_id);if(sqlite3_step(st)==SQLITE_ROW){wchar_t value[300];MultiByteToWideChar(CP_UTF8,0,(const char*)sqlite3_column_text(st,0),-1,value,300);SetWindowTextW(time_edit,value);SendMessageW(type_box,CB_SETCURSEL,!strcmp((const char*)sqlite3_column_text(st,1),"income")?1:0,0);load_categories();int count=(int)SendMessageW(category_box,CB_GETCOUNT,0,0);for(int i=0;i<count;i++)if((int)SendMessageW(category_box,CB_GETITEMDATA,i,0)==sqlite3_column_int(st,2))SendMessageW(category_box,CB_SETCURSEL,i,0);swprintf(value,300,L"%.2f",sqlite3_column_int(st,3)/100.0);SetWindowTextW(amount_edit,value);MultiByteToWideChar(CP_UTF8,0,(const char*)sqlite3_column_text(st,4),-1,value,300);SetWindowTextW(note_edit,value);}sqlite3_finalize(st);
}

static void delete_selected(void) {int row=ListView_GetNextItem(list_view,-1,LVNI_SELECTED);if(row<0){message(L"请先选择一笔账目。");return;}if(MessageBoxW(NULL,L"确定删除这笔账目？",L"确认",MB_YESNO|MB_ICONWARNING)!=IDYES)return;LVITEMW item={.mask=LVIF_PARAM,.iItem=row};ListView_GetItem(list_view,&item);sqlite3_stmt *st=NULL;sqlite3_prepare_v2(db,"DELETE FROM transactions WHERE id=?",-1,&st,NULL);sqlite3_bind_int(st,1,(int)item.lParam);sqlite3_step(st);sqlite3_finalize(st);refresh_list();}
static void save_budget(void){char month[16];selected_month(month,sizeof month);int category=ensure_category();wchar_t value[32];text_of(budget_edit,value,32);double amount=wcstod(value,NULL);if(!category||amount<0){message(L"请选择类别并填写非负预算。");return;}sqlite3_stmt *st=NULL;sqlite3_prepare_v2(db,"INSERT INTO budgets(month,category_id,amount_cents) VALUES(?,?,?) ON CONFLICT(month,category_id) DO UPDATE SET amount_cents=excluded.amount_cents",-1,&st,NULL);sqlite3_bind_text(st,1,month,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,category);sqlite3_bind_int(st,3,(int)(amount*100+.5));sqlite3_step(st);sqlite3_finalize(st);refresh_summary();}
static void csv_write_field(FILE *file,const char *value){const unsigned char *first=(const unsigned char*)value;while(*first==' '||*first=='\t'||*first=='\r'||*first=='\n')first++;bool formula=*first=='='||*first=='+'||*first=='-'||*first=='@';fputc('"',file);if(formula)fputc('\'',file);for(const unsigned char *p=(const unsigned char*)value;*p;p++){if(*p=='"')fputc('"',file);fputc(*p,file);}fputc('"',file);}
static void export_csv(void){char month[16],file[64];selected_month(month,sizeof month);snprintf(file,sizeof file,"finance-%s.csv",month);FILE *f=fopen(file,"wb");if(!f){message(L"无法创建 CSV 文件。");return;}fprintf(f,"date,time,type,category,amount,note\n");sqlite3_stmt *st=NULL;sqlite3_prepare_v2(db,"SELECT t.record_date,t.record_time,t.type,c.name,t.amount_cents,t.note FROM transactions t JOIN categories c ON c.id=t.category_id WHERE substr(t.record_time,1,7)=? ORDER BY t.record_time",-1,&st,NULL);sqlite3_bind_text(st,1,month,-1,SQLITE_TRANSIENT);while(sqlite3_step(st)==SQLITE_ROW){csv_write_field(f,(const char*)sqlite3_column_text(st,0));fputc(',',f);csv_write_field(f,(const char*)sqlite3_column_text(st,1));fputc(',',f);csv_write_field(f,(const char*)sqlite3_column_text(st,2));fputc(',',f);csv_write_field(f,(const char*)sqlite3_column_text(st,3));fprintf(f,",%.2f,",sqlite3_column_int(st,4)/100.0);csv_write_field(f,(const char*)sqlite3_column_text(st,5));fputc('\n',f);}sqlite3_finalize(st);bool ok=!ferror(f);if(fclose(f)!=0)ok=false;message(ok?L"已在程序目录导出 CSV 文件。":L"CSV 导出未能完整写入，请检查磁盘空间和权限。");}

static HWND make(HWND parent,const wchar_t *kind,const wchar_t *text,DWORD style,int x,int y,int w,int h,int id){return CreateWindowW(kind,text,WS_CHILD|WS_VISIBLE|style,x,y,w,h,parent,(HMENU)(INT_PTR)id,GetModuleHandleW(NULL),NULL);}
static LRESULT CALLBACK window_proc(HWND window,UINT msg,WPARAM w,LPARAM l){
    if(msg==WM_CREATE){
        SetWindowPos(window,NULL,0,0,980,1030,SWP_NOMOVE|SWP_NOZORDER);
        make(window,L"STATIC",L"查看月份",0,740,65,60,24,0);
        month_edit=make(window,L"EDIT",L"",WS_BORDER,805,62,110,24,ID_MONTH);
        wchar_t now[32];now_text(now,32);now[7]=0;SetWindowTextW(month_edit,now);
        make(window,L"BUTTON",L"查看全部历史",BS_PUSHBUTTON,600,108,120,30,ID_HISTORY);
        available_text=make(window,L"STATIC",L"目前可支配金额：¥0.00",0,25,155,900,28,0);
        make(window,L"STATIC",L"设置当前余额",0,25,190,100,24,0);
        balance_edit=make(window,L"EDIT",L"0.00",WS_BORDER|ES_AUTOHSCROLL,130,187,130,26,ID_SET_BALANCE);
        make(window,L"BUTTON",L"保存余额",BS_PUSHBUTTON,270,186,90,28,ID_SET_BALANCE);
        summary_text=make(window,L"STATIC",L"",0,25,220,900,24,0);
        list_view=make(window,WC_LISTVIEWW,L"",LVS_REPORT|LVS_SINGLESEL|WS_BORDER,25,248,900,362,ID_LIST);
        const wchar_t *heads[]={L"记录时间",L"类型",L"类别",L"金额",L"备注"};int widths[]={170,70,120,100,400};
        for(int i=0;i<5;i++){LVCOLUMNW col={0};col.mask=LVCF_TEXT|LVCF_WIDTH;col.pszText=(LPWSTR)heads[i];col.cx=widths[i];ListView_InsertColumn(list_view,i,&col);}
        make(window,L"STATIC",L"近 24 个月收支对比",0,25,625,220,24,0);
        comparison_view=make(window,WC_LISTVIEWW,L"",LVS_REPORT|WS_BORDER,25,650,900,280,ID_COMPARISON);
        const wchar_t *comparison_heads[]={L"月份",L"收入",L"支出",L"结余"};int comparison_widths[]={200,220,220,220};
        for(int i=0;i<4;i++){LVCOLUMNW col={0};col.mask=LVCF_TEXT|LVCF_WIDTH;col.pszText=(LPWSTR)comparison_heads[i];col.cx=comparison_widths[i];ListView_InsertColumn(comparison_view,i,&col);}
        return 0;
    }
    if(msg==WM_COMMAND){
        int id=LOWORD(w);
        if(id==ID_TYPE&&HIWORD(w)==CBN_SELCHANGE){load_categories();return 0;}
        if(id==ID_ADD){save_transaction(0);return 0;}
        if(id==ID_UPDATE){if(editing_id)save_transaction(1);else edit_selected();return 0;}
        if(id==ID_DELETE){delete_selected();return 0;}
        if(id==ID_REFRESH||id==ID_MONTH){refresh_list();return 0;}
        if(id==ID_HISTORY){show_all_history=!show_all_history;SetWindowTextW((HWND)l,show_all_history?L"仅看本月":L"查看全部历史");refresh_list();return 0;}
        if(id==ID_EXPORT){export_csv();return 0;}
        if(id==ID_SAVE_BUDGET){save_budget();return 0;}
        if(id==ID_SET_BALANCE&&HIWORD(w)==BN_CLICKED){set_current_balance();return 0;}
    }
    if(msg==WM_DESTROY){sqlite3_close(db);PostQuitMessage(0);return 0;}
    return DefWindowProcW(window,msg,w,l);
}

int WINAPI WinMain(HINSTANCE instance,HINSTANCE previous,LPSTR command,int show){
    (void)previous;(void)command;(void)show;
    INITCOMMONCONTROLSEX init={sizeof init,ICC_LISTVIEW_CLASSES};
    InitCommonControlsEx(&init);
    if(!open_database()){message(L"无法打开 SQLite 数据库。");return 1;}
    WNDCLASSW wc={0};
    wc.hInstance=instance;wc.lpszClassName=L"CampusFinance";wc.lpfnWndProc=window_proc;
    wc.hCursor=LoadCursor(NULL,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    RegisterClassW(&wc);
    HWND window=CreateWindowW(wc.lpszClassName,L"校园财务台 · C 桌面版",
        WS_OVERLAPPEDWINDOW|WS_VISIBLE,100,100,980,680,NULL,NULL,instance,NULL);
    make(window,L"STATIC",L"类型",0,25,25,70,24,0);
    type_box=make(window,L"COMBOBOX",L"",CBS_DROPDOWNLIST,95,22,130,200,ID_TYPE);
    SendMessageW(type_box,CB_ADDSTRING,0,(LPARAM)L"支出");
    SendMessageW(type_box,CB_ADDSTRING,0,(LPARAM)L"收入");
    SendMessageW(type_box,CB_SETCURSEL,0,0);
    make(window,L"STATIC",L"类别",0,245,25,50,24,0);
    category_box=make(window,L"COMBOBOX",L"",CBS_DROPDOWN,290,22,150,200,ID_CATEGORY);
    make(window,L"STATIC",L"记录时间",0,25,65,70,24,0);
    time_edit=make(window,L"EDIT",L"",WS_BORDER,95,62,160,24,ID_TIME);
    wchar_t now[32];now_text(now,32);SetWindowTextW(time_edit,now);
    make(window,L"STATIC",L"金额",0,275,65,45,24,0);
    amount_edit=make(window,L"EDIT",L"",WS_BORDER,320,62,120,24,ID_AMOUNT);
    make(window,L"STATIC",L"备注",0,460,25,45,24,0);
    note_edit=make(window,L"EDIT",L"",WS_BORDER,505,22,420,24,ID_NOTE);
    make(window,L"STATIC",L"本类预算",0,460,65,65,24,0);
    budget_edit=make(window,L"EDIT",L"0",WS_BORDER,525,62,100,24,ID_BUDGET);
    make(window,L"BUTTON",L"保存预算",BS_PUSHBUTTON,635,61,90,26,ID_SAVE_BUDGET);
    make(window,L"BUTTON",L"新增账目",BS_PUSHBUTTON,25,108,100,30,ID_ADD);
    make(window,L"BUTTON",L"编辑选中",BS_PUSHBUTTON,135,108,100,30,ID_UPDATE);
    make(window,L"BUTTON",L"删除选中",BS_PUSHBUTTON,245,108,100,30,ID_DELETE);
    make(window,L"BUTTON",L"刷新统计",BS_PUSHBUTTON,355,108,100,30,ID_REFRESH);
    make(window,L"BUTTON",L"导出本月 CSV",BS_PUSHBUTTON,465,108,120,30,ID_EXPORT);
    load_categories();
    refresh_list();
    MSG message_loop;
    while(GetMessageW(&message_loop,NULL,0,0)){TranslateMessage(&message_loop);DispatchMessageW(&message_loop);}
    return 0;
}
