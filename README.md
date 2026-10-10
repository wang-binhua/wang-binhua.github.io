# Campus Finance（C 全栈个人财务系统）

项目展示页：<https://wang-binhua.github.io/>（仓库发布到 GitHub Pages 后可访问）

这个项目包含 C 语言原生桌面程序和本机网页服务；二者通过 SQLCipher 加密 SQLite 数据库保存账目，网页前端使用 HTML、CSS、JavaScript。

功能包括收入/支出记录、可扩展类别、月度分类统计、分类预算、目前可支配金额、图表、编辑/删除账目和按月导出 CSV。数据保存在 `data/finance.db`。

## 构建

安装 CMake、C 编译器、OpenSSL 和 SQLCipher 开发包后，在本目录执行：

```powershell
cmake -S . -B build -DCMAKE_PREFIX_PATH=C:/msys64/ucrt64
cmake --build build --config Release
```

Windows MSYS2 UCRT64 用户可以安装所需依赖：

```powershell
& C:\msys64\usr\bin\pacman.exe -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-sqlcipher mingw-w64-ucrt-x86_64-openssl
```

从项目根目录启动生成的 `campus_finance.exe`，再打开 `http://127.0.0.1:8080`。服务只监听 IPv4 回环地址 `127.0.0.1`；不要改成 `0.0.0.0` 或电脑的热点网卡地址。

## 结构

- `src/main.c`：HTTP 路由、请求校验、SQLite 查询和 JSON API
- `web/`：仪表盘网页
- `CMakeLists.txt`：构建配置

## API

| 方法 | 地址 | 用途 |
| --- | --- | --- |
| `GET` | `/api/auth/status` | 检查账本是否已初始化 |
| `POST` | `/api/auth/setup`、`/api/auth/login`、`/api/auth/recover` | 初始化、登录或用恢复密钥重设密码 |
| `POST` | `/api/auth/logout` | 锁定账本并结束当前会话 |
| `GET` / `POST` | `/api/transactions` | 查询或新增账目 |
| `PUT` / `DELETE` | `/api/transactions/{id}` | 编辑或删除账目 |
| `GET` | `/api/dashboard?month=YYYY-MM` | 读取月度汇总、分类支出及目前可支配金额 |
| `PUT` | `/api/balance` | 设置当前可支配金额（JSON：`{"amount":1234.56}`） |
| `GET` / `PUT` | `/api/budgets?month=YYYY-MM` | 读取或更新分类预算 |
| `GET` | `/api/export?month=YYYY-MM` | 下载当月 CSV |

后续值得做的扩展：按天趋势图、CSV 导入、月度变化率、自动备份、测试和 GitHub Actions。

## Windows 桌面版

`build/finance_desktop.exe` 是 CMake 构建的不需要浏览器的原生桌面程序；桌面快捷方式“校园财务台”指向该程序，并以项目根目录为工作目录。它和网页版本共用 `data/finance.db`，所以两边录入的账目会同步显示。

每笔账目使用 `YYYY-MM-DD HH:MM` 保存具体记录时间。桌面版支持新建/编辑/删除账目、自定义类别、分类预算、月度汇总和 CSV 导出。网页仪表盘和桌面版都显示目前可支配金额，可在“设置当前余额”处输入此刻实际可支配金额；已存在的账目会作为校准时的快照，不会再次改变该金额，之后新增的收入和支出会自动更新余额。账目明细默认显示所选月份，可切换为查看全部历史；窗口下方按月份汇总最近 24 个有记录的月份，便于对比收入、支出和结余。没有录入账目的月份不会显示在对比表中。

桌面快捷方式“校园财务台”启动 `finance_desktop.exe`，并以项目目录作为工作目录；数据库保存在 `data/finance.db`。若历史列表或月度对比为空，请先录入账目。

## 安全说明

- 第一次启动桌面版或网页服务时，创建至少 12 个字符的账本密码；两个入口共用同一凭据。网页/API 在登录前不会返回账目数据；登录会话闲置 15 分钟后过期，点击“锁定账本”可立即注销。
- 首次设置会生成一次性 256 位恢复密钥。请离线保存；忘记密码时用它设置新密码。每次恢复都会同时更换恢复密钥，让旧恢复密钥立即失效。密码建议存放在可信的密码管理器；恢复密钥可保存为独立的加密安全笔记或纸质副本，不要与账本数据库放在同一目录。
- SQLCipher 使用 AES-256 加密 `data/finance.db`；主密钥由 OpenSSL AES-256-GCM 分别用密码和恢复密钥保护，密钥派生使用 PBKDF2-HMAC-SHA256。现有 SQLite 数据库先导出并验证加密副本，再原子替换原文件；凭据文件会记录迁移状态，以便意外中断后安全续做，不创建明文迁移备份。
- 原有明文数据库、Windows 卷影副本、旧备份或 SSD 历史块不会因文件被替换而可靠擦除；首次加密前请确认其他明文副本也妥善保护。
- 备份时需一起保存 `data/finance.db` 和 `data/credentials.bin`，并确保恢复密钥也已安全备份。CSV 导出和你另存的备份文件不是自动加密的。
- 服务严格绑定 `127.0.0.1:8080`，并拒绝其他 `Host`、非本地写入来源及非 JSON 写请求；这可阻止热点上的其他设备直接连入，但不能阻止这台电脑上的恶意程序。仍应保护 Windows 账户、保持系统更新，并启用可用的磁盘加密。

## 维护者安全检查清单

- 两个可执行程序必须链接同一套 SQLCipher；不可退回普通 SQLite，也不可忽略解密、迁移或密钥保存错误。
- 监听地址保持 `INADDR_LOOPBACK`，Host/Origin 检查和 API 会话认证不得绕过；增加或改动路由时确认数据读取、导出和写操作都受认证保护。
- 任何真实账本、凭据文件、恢复密钥或 CSV 都不要加入 Git。安全测试使用独立临时数据库；运行 `ctest --test-dir build --output-on-failure` 验证迁移、密码轮换和旧恢复密钥撤销。
- 修改加密/迁移流程时，验证迁移前数据保留、进程在替换前后中断都可恢复，且不得生成或保留明文迁移备份。定期更新并核验 MSYS2、SQLCipher 和 OpenSSL 依赖。

如果电脑安装了 MinGW UCRT64，可直接构建：

```powershell
gcc -std=c17 -O2 -DSQLITE_HAS_CODEC -IC:/msys64/ucrt64/include/sqlcipher -mwindows src/desktop_main.c src/security.c -o build/finance_desktop.exe -LC:/msys64/ucrt64/lib -lsqlcipher -lcrypto -lcomctl32
gcc -std=c17 -O2 -DSQLITE_HAS_CODEC -IC:/msys64/ucrt64/include/sqlcipher src/main.c src/security.c -o campus_finance.exe -LC:/msys64/ucrt64/lib -lsqlcipher -lcrypto -lws2_32
```
