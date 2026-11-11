# agentssh — Thiết kế (MVP)

- Ngày: 2026-11-10
- Trạng thái: chờ review
- Người dùng mục tiêu: cá nhân + đồng nghiệp, phát hành open-source (Apache-2.0)

## 1. Bài toán

AI agent (Claude Code, Codex) cần chạy lệnh trên server qua SSH. Hiện có ba lựa chọn, đều thiếu:

- Cho agent dùng `ssh` trực tiếp: agent dùng được key cá nhân, không có policy, không audit riêng.
- SSH MCP server cộng đồng: thường không có bước duyệt, allowlist tùy chọn, key nằm cùng chỗ agent chạy, nhiều tool nên tốn token.
- Sản phẩm thương mại (Termalin, Conduit): có key custody và policy theo host (full/allowlist/blocked) nhưng không có duyệt theo mức rủi ro, không scope theo repo, không rõ license.

Ngoài ra nghiên cứu (Straiker, 08/2026) cho thấy agent bị prompt injection có thể tự viết mô tả vô hại cho bước duyệt trong khi lệnh thật nguy hiểm. Bước duyệt phải hiển thị lệnh gốc và mức rủi ro do tool tính, không dùng mô tả của agent.

## 2. Mục tiêu và ngoài phạm vi

Mục tiêu MVP:

1. Agent không bao giờ thấy private key.
2. Mọi lệnh được phân loại tất định (không dùng LLM) thành `read` / `mutate` / `destructive` / `forbidden`.
3. Lệnh `destructive` bắt buộc người duyệt qua kênh ngoài agent; `forbidden` luôn bị chặn.
4. Output gọn, tiết kiệm token; output đầy đủ lấy lại được khi cần.
5. Cài đặt bằng một binary, chạy trên Linux và macOS (amd64, arm64).
6. Mọi hành động được ghi audit.

Ngoài phạm vi MVP (lộ trình sau):

- V1.1: chế độ hardened (daemon chạy bằng system user riêng).
- V2: chế độ MCP, SSH certificate CA ngắn hạn, tmux watch/attach, thu thập thông tin host, backup/undo khi ghi file.
- Sau nữa: Windows, GUI, duyệt trên mobile, vault dùng chung cho team.

Không làm: server trung tâm, đồng bộ cloud, quản lý team. Mỗi người tự cài và tự quản host/key của mình; chia sẻ chỉ qua file `.agentssh.toml` (không chứa secret) trong git.

## 3. Kiến trúc

Một binary Go `agentssh` có hai vai:

- `agentssh daemon`: tiến trình nền, chạy như user service (systemd `--user` trên Linux, launchd trên macOS). Lắng nghe Unix socket `$XDG_RUNTIME_DIR/agentssh.sock` (macOS: thư mục tương đương trong `~/Library/Application Support/agentssh/`), quyền `0600`, kiểm tra peer UID (`SO_PEERCRED` trên Linux, `getpeereid` trên macOS) để chỉ chấp nhận cùng user.
- Các subcommand còn lại là client mỏng, gọi daemon qua `net/rpc/jsonrpc` (stdlib).

```text
Claude Code / Codex (Bash)
        │  agentssh run ...
        ▼
  agentssh CLI ── unix socket 0600 ──► agentssh daemon
                                         ├─ vault     (key chỉ trong RAM)
                                         ├─ hosts     (hosts.toml)
                                         ├─ policy    (parser + rule + profile)
                                         ├─ approval  (hàng đợi + thông báo + mã)
                                         ├─ sshconn   (pool, exec, sftp, job)
                                         └─ audit     (JSONL)
                                                │ SSH
                                                ▼
                                             servers
```

### Package

| Package | Trách nhiệm |
|---|---|
| `vault` | Mã hóa/giải mã kho key; giữ key đã giải mã trong RAM |
| `hosts` | Đọc `hosts.toml`, import từ `~/.ssh/config` |
| `policy` | Parse lệnh, phân loại, gộp profile host + repo, trả quyết định |
| `approval` | Hàng đợi request chờ duyệt, sinh mã, gửi thông báo |
| `sshconn` | Pool kết nối, exec, SFTP, job nền, known_hosts riêng |
| `audit` | Ghi JSONL |
| `hook` | Chuyển JSON hook của agent thành quyết định allow/ask/deny |
| `cli` | Các subcommand |

### Dependency ngoài

`golang.org/x/crypto` (ssh, nacl/secretbox, argon2), `mvdan.cc/sh/v3` (parser shell), `github.com/zalando/go-keyring`, `github.com/pkg/sftp`, một thư viện TOML (`github.com/BurntSushi/toml`). Không thêm gì khác cho MVP.

### File

| Đường dẫn | Nội dung |
|---|---|
| `~/.config/agentssh/hosts.toml` | Host, profile, deny/allow riêng (không secret) |
| `~/.config/agentssh/rules.toml` | Override bảng rule (tùy chọn) |
| `~/.config/agentssh/vault.bin` | Kho key đã mã hóa |
| `~/.config/agentssh/known_hosts` | Host key đã chấp nhận |
| `~/.local/state/agentssh/audit.jsonl` | Audit log |
| `~/.local/state/agentssh/out/<id>` | Output đầy đủ, xóa sau 7 ngày |

## 4. Policy engine

### 4.1 Phân loại lệnh

1. Parse chuỗi lệnh bằng `mvdan.cc/sh/v3/syntax`. Lỗi parse ⇒ `destructive`.
2. Duyệt mọi lệnh con trong AST: pipe, `&&`, `||`, `;`, subshell, `$(...)`, backtick, process substitution.
3. Chuẩn hóa tên lệnh: bỏ đường dẫn (`/usr/bin/rm` → `rm`); bóc wrapper `sudo`, `env`, `nohup`, `timeout`, `nice`, `xargs`, `stdbuf` (kèm các flag của chúng). `bash -c` / `sh -c` với chuỗi literal ⇒ parse đệ quy.
4. Tên lệnh không tĩnh (`$x`, `eval`, `bash -c "$y"`, `source` file không biết nội dung) ⇒ `destructive`.
5. Khớp từng lệnh con với bảng rule. Lệnh không có trong bảng ⇒ `mutate`.
6. Redirect ghi file (`>`, `>>`, `tee`) ⇒ tối thiểu `mutate`; ghi vào `/etc`, `/boot`, `/usr`, `/var/lib` ⇒ `destructive`.
7. Mức của cả câu lệnh = mức cao nhất trong các lệnh con. Thứ tự: `read` < `mutate` < `destructive` < `forbidden`.

Kết quả trả về gồm mức, danh sách lý do (lệnh con nào, rule nào) và vị trí ký tự để tô màu khi duyệt.

### 4.2 Bảng rule mặc định (nhúng trong binary, user override qua `rules.toml`)

Rule khớp theo tên lệnh + tiền tố đối số (glob), ví dụ `systemctl stop *`, `docker system prune*`, `find * -delete*`.

- `read`: `ls cat head tail grep rg awk`, `sed` (không `-i`), `ps df du free uptime uname whoami id hostname ip ss netstat lsof stat file wc sort uniq date env printenv which`, `systemctl status|is-active|list-units`, `journalctl`, `docker ps|logs|inspect|images|stats --no-stream`, `git status|log|diff|show`, `find` (không `-delete`, `-exec`, `-execdir`), `curl`/`wget` không ghi file và không pipe vào shell.
- `mutate`: `systemctl restart|reload|start`, `docker restart|start|pull|compose up`, `mkdir cp mv touch ln`, `sed -i`, `apt|dnf|yum|apk install|update`, `pip|npm install`, `git pull|fetch|checkout`, `kill` (không `-9`).
- `destructive`: `rm rmdir dd mkfs* fdisk parted shred wipefs reboot shutdown poweroff halt`, `systemctl stop|disable|mask`, `docker rm|rmi|down|system prune|volume rm`, `kill -9`, `pkill killall`, `iptables nft ufw`, `chmod -R`, `chown -R`, `truncate`, `crontab -r`, `userdel usermod passwd`, `apt remove|purge`, SQL chứa `DROP|TRUNCATE|DELETE|ALTER` trong `psql -c`, `mysql -e`, `sqlite3`.
- `forbidden`: mọi tham chiếu tới `~/.ssh`, `authorized_keys`, `id_rsa*`, `id_ed25519*`, `/etc/shadow`, `/etc/sudoers*`; tải về rồi pipe vào shell (`curl … | sh`, `wget -O- … | bash`); `base64 -d | sh`; reverse shell (`nc -e`, `bash -i >& /dev/tcp/…`).

### 4.3 Profile host

| Profile | read | mutate | destructive | forbidden |
|---|---|---|---|---|
| `readonly` | chạy | chặn | chặn | chặn |
| `standard` (mặc định) | chạy | hỏi qua prompt agent (tầng mềm) | duyệt riêng qua daemon | chặn |
| `full` | chạy | chạy | duyệt riêng qua daemon | chặn |

Mỗi host còn có:

- `agent = true|false` (mặc định `false`): host chỉ hiện với agent khi bật.
- `deny = [...]`, `allow = [...]`: pattern bổ sung. `deny` đẩy lệnh khớp lên `forbidden`; `allow` hạ lệnh khớp xuống `read` nhưng không bao giờ hạ được `forbidden` mặc định.

Ví dụ `hosts.toml`:

```toml
[hosts.web1]
host = "10.0.0.5"
user = "deploy"
port = 22
key = "web1-agent"        # tên key trong vault
profile = "standard"
agent = true
description = "nginx + app server production"
allow = ["docker compose -f /srv/app/compose.yml restart *"]
deny  = ["psql *"]
```

### 4.4 File `.agentssh.toml` trong repo

CLI gửi cwd lên daemon; daemon tìm `.agentssh.toml` từ cwd đi ngược lên thư mục gốc.

```toml
hosts = ["web1", "db-staging"]
max_profile = "standard"
```

- Có file: agent chỉ thấy các host trong danh sách; profile hiệu lực = mức chặt hơn giữa profile host và `max_profile`.
- Không có file: dùng cấu hình toàn cục (mọi host có `agent = true`).
- File chỉ thu hẹp quyền, không bao giờ nới rộng.
- Đây là cơ chế giới hạn phạm vi cho tiện và tránh nhầm host. Không phải ranh giới bảo mật, vì cwd do client tự khai.

### 4.5 Hai tầng bảo vệ

- Tầng cứng (daemon tự bắt buộc, áp dụng mọi agent): chặn `forbidden`, chặn theo profile, bắt duyệt riêng cho `destructive`.
- Tầng mềm (hook của agent, chỉ có khi đã cài hook): hỏi người dùng khi gặp `mutate` trong profile `standard`; chặn `ssh`/`scp`/`rsync`/`sftp` trực tiếp; chặn agent gọi lệnh quản trị.

Không cài hook thì `mutate` trong profile `standard` chạy không hỏi. `agentssh doctor` cảnh báo trường hợp này.

## 5. Luồng duyệt và vault

### 5.1 Luồng duyệt lệnh `destructive`

1. Daemon tạo request: id, thời điểm, host, user remote, cwd, repo, agent (suy từ biến môi trường do CLI gửi kèm, ví dụ `CLAUDECODE`, `CODEX_*`), lệnh gốc, mức, lý do, vị trí cần tô màu.
2. Daemon sinh mã duyệt 4 ký tự (bảng chữ không gây nhầm lẫn, ví dụ bỏ `0 O 1 I`) và gửi thông báo desktop (`notify-send` trên Linux, `osascript display notification` trên macOS): `web1: rm -rf /var/log/old [destructive] code: K7Q4`.
3. CLI chặn chờ, in ra stderr `waiting approval #12 — run 'agentssh approve' in another terminal`. Timeout mặc định 120 giây ⇒ từ chối, exit `101`.
4. Người dùng chạy `agentssh approve` ở terminal khác. TUI hiển thị đầy đủ request (lệnh gốc tô màu, lý do), yêu cầu gõ mã, rồi chọn:
   - `y`: chỉ lần này
   - `s`: cho phép lệnh giống hệt (cùng host, cùng chuỗi) trong 30 phút
   - `n`: từ chối
   - `m`: từ chối kèm lời nhắn; lời nhắn được trả về cho agent trong stderr
5. Nhập sai mã 3 lần ⇒ request bị từ chối và ghi audit.

### 5.2 Quy tắc chung cho thao tác quản trị

Mọi thao tác sau cần mã duyệt hiển thị qua thông báo desktop: approve, reload hoặc sửa config qua CLI, thêm/xóa/xuất key, chấp nhận host key mới, bật `agent = true` cho host. Lệnh quản trị bắt buộc chạy trên terminal thật (mở được `/dev/tty`); TUI không bao giờ in mã ra màn hình.

Daemon chỉ đọc lại `hosts.toml` và `rules.toml` khi có lệnh `agentssh reload` đã duyệt bằng mã, hoặc khi khởi động. Khi khởi động, nếu hash config khác hash đã lưu trong vault, daemon chạy ở chế độ chỉ cho người dùng (từ chối mọi request agent) cho tới khi người dùng xác nhận bằng mã.

### 5.3 Mô hình đe dọa

- Chế độ mặc định (daemon chạy cùng user): chống agent bị prompt injection lợi dụng các tool thông thường (Bash, Edit, Write) để lấy key, chạy lệnh nguy hiểm không duyệt, hoặc tự duyệt. Không chống tiến trình độc hại cùng user cố tình tấn công (có thể đọc keyring, debug tiến trình, đọc màn hình).
- Chế độ hardened (V1.1): daemon chạy bằng system user `agentssh`, socket mở cho group `agentssh`, vault mở khóa bằng passphrase. Agent không đọc được vault, config hay bộ nhớ daemon. Đây là ranh giới bảo mật thật.
- Tài liệu phải nêu rõ hai mức này.

### 5.4 Vault

- `vault.bin` mã hóa bằng `nacl/secretbox`. Master key: 32 byte ngẫu nhiên lưu trong OS keyring (mặc định), hoặc dẫn xuất từ passphrase bằng `argon2id` (khi không có keyring).
- Nội dung: private key (đặt tên), password (hỗ trợ nhưng không khuyến khích), hash config.
- `agentssh key gen <name>` tạo ed25519 và in public key để thêm vào `authorized_keys`. Tài liệu khuyến khích mỗi agent dùng key riêng, không dùng key cá nhân.
- `agentssh key import <name> <path>` nhập key có sẵn (cần mã duyệt).
- Daemon giải mã khi `unlock` (tự động qua keyring khi khởi động, hoặc nhập passphrase), giữ key trong RAM, thử `mlock`. `agentssh lock` xóa key khỏi RAM.
- Không có API nào trả dữ liệu key qua socket. Xuất key chỉ qua `agentssh key export` trên terminal thật, có mã duyệt.
- Kiểm tra host key nghiêm ngặt với `known_hosts` riêng; host chưa biết hoặc host key thay đổi ⇒ từ chối, cần người dùng chấp nhận bằng mã.

### 5.5 Audit

Mỗi dòng JSONL: thời điểm, request id, agent, cwd, repo, host, lệnh gốc, mức, quyết định (allow/ask/approved/denied/forbidden/timeout), người duyệt có nhập đúng mã không, exit code, thời gian chạy, số byte output. Không ghi nội dung output vào audit (output nằm trong `out/` và tự xóa sau 7 ngày).

## 6. CLI, skill, hook

### 6.1 Lệnh cho agent

```text
agentssh hosts [--json]
agentssh run <host> "<cmd>" [--timeout 60s] [--json]
agentssh out <id> [--grep <pattern>] [--range a:b]
agentssh get <host>:<remote-path> <local-path>
agentssh put <local-path> <host>:<remote-path>
agentssh job start <host> "<cmd>"
agentssh job tail <id> [--lines N]
agentssh job kill <id>
agentssh explain "<cmd>" [--host <host>]
```

- `hosts`: liệt kê host agent được thấy (đã lọc theo repo): tên, profile hiệu lực, mô tả.
- `run`: dòng đầu `web1 exit=0 1.2s level=read id=57`, sau đó stdout và stderr. Output dài hơn 80 dòng: in 40 dòng đầu, dòng `… N lines omitted, full: agentssh out 57`, rồi 40 dòng cuối. Timeout mặc định 60 giây.
- Không cấp PTY. Lệnh tương tác đã biết (`vim`, `nano`, `top`, `htop`, `less`, `watch`, `ssh`) bị từ chối với gợi ý thay thế (`top -bn1`, `cat`, …).
- `put` có mức `mutate`; ghi vào đường dẫn hệ thống ở 4.1 bước 6 ⇒ `destructive`. Giới hạn kích thước mặc định 50 MB.
- `job`: daemon giữ phiên SSH và đệm output của job. Daemon khởi động lại thì mất job (ghi rõ trong docs).
- `explain`: trả kết quả phân loại, không chạy gì.

Exit code: lệnh remote trả mã gì thì giữ nguyên. Mã riêng của agentssh:

- `100`: policy chặn (`forbidden`, profile không cho phép, host không được phép)
- `101`: bị từ chối hoặc hết thời gian chờ duyệt
- `102`: daemon không chạy hoặc vault đang khóa

Mỗi mã riêng kèm một dòng stderr hướng dẫn agent (ví dụ với `101`: "dừng lại và hỏi người dùng, không thử lại bằng cách khác").

Để phân biệt khi lệnh remote tình cờ thoát với mã `100`–`102`: chỉ mã do agentssh sinh ra mới kèm dòng stderr có tiền tố `agentssh:`.

### 6.2 Lệnh cho người

`init`, `unlock`, `lock`, `host add|edit|ls|rm`, `key gen|import|export|ls|rm`, `approve`, `reload`, `log [--follow]`, `doctor`, `install-hooks claude|codex`, `daemon`.

`init` thực hiện: tạo master key trong keyring, tạo vault, import `~/.ssh/config` (mọi host mặc định `agent = false`), cài user service, cài skill và hook (hỏi trước).

`doctor` kiểm tra: daemon chạy, vault mở, hook đã cài, có deny rule cho `ssh` trực tiếp, thông báo desktop hoạt động, key cá nhân trong `~/.ssh` có passphrase.

### 6.3 Skill và hướng dẫn cho agent

- Claude Code: `~/.claude/skills/agentssh/SKILL.md` (khoảng 40 dòng): khi nào dùng, các lệnh, ý nghĩa exit code, quy tắc (không gọi `ssh` trực tiếp, không gọi `approve`/`key`/`reload`, gặp `101` thì dừng và hỏi người dùng, dùng `out --grep` thay vì chạy lại lệnh).
- Codex: đoạn tương đương thêm vào `~/.codex/AGENTS.md`.

### 6.4 Hook

Claude Code, `PreToolUse` (cài vào `~/.claude/settings.json`, gọi `agentssh hook claude`):

- Tool `Bash`: parse lệnh bằng cùng parser.
  - Có lệnh con `ssh`, `scp`, `sftp`, `rsync` (có remote), `mosh` ⇒ `deny`, lý do: "dùng agentssh run".
  - Có `agentssh approve|key|reload|host|init|install-hooks` ⇒ `deny`.
  - Có `agentssh run <host> "<cmd>"` ⇒ hỏi daemon phân loại `<cmd>` với profile hiệu lực: `read` ⇒ `allow`; `mutate` ⇒ `ask` nếu profile `standard`, `allow` nếu `full`; `destructive` ⇒ `allow` (daemon sẽ bắt duyệt riêng, tránh duyệt hai lần); `forbidden` hoặc profile chặn ⇒ `deny`.
  - Daemon không phản hồi ⇒ `ask`.
- Tool `Edit`, `Write`, `NotebookEdit`: đường dẫn nằm trong `~/.config/agentssh` hoặc `~/.local/state/agentssh` ⇒ `deny`.

Codex: lúc implement kiểm tra cơ chế rules/hook hiện có của Codex và dùng nếu có. Tối thiểu: đoạn AGENTS.md và tầng cứng của daemon.

## 7. Xử lý lỗi

- Mất kết nối SSH giữa chừng: trả lỗi rõ ràng (exit `255` như `ssh`), xóa kết nối khỏi pool, lần sau kết nối lại.
- Lệnh vượt timeout: gửi signal kết thúc qua kênh SSH, đóng session, exit `124` (giống `timeout`).
- Daemon chết khi CLI đang chờ: CLI báo lỗi, exit `102`.
- Keyring không khả dụng (máy headless): `init` chuyển sang chế độ passphrase.
- Không gửi được thông báo desktop: request vẫn chờ; `approve` trên terminal thật hiển thị mã trực tiếp (vì kênh desktop không có). `doctor` cảnh báo rằng ở chế độ này agent có thể tự duyệt nếu giả lập được TTY, và khuyên dùng chế độ hardened.

## 8. Kiểm thử

- `policy`: test dạng bảng khoảng 100 lệnh, gồm các trường hợp lách: `ls; rm -rf /`, `echo $(cat ~/.ssh/id_rsa)`, `sudo -u x bash -c 'dd if=/dev/zero of=/dev/sda'`, `/usr/bin/rm`, `curl x | sh`, `find / -delete`, `X=rm; $X -rf /`, heredoc chứa lệnh, chuỗi thoát ký tự.
- `sshconn` + `daemon`: test tích hợp với SSH server chạy trong tiến trình test, dựng bằng `x/crypto/ssh` (không cần Docker).
- `hook`: JSON mẫu của Claude Code đưa vào stdin, kiểm tra quyết định trả về.
- `vault`: mã hóa/giải mã vòng tròn, sai master key thì lỗi.
- `approval`: mã sai 3 lần bị từ chối; timeout; `s` chỉ áp dụng cho lệnh giống hệt.

## 9. Phát hành

- Binary trên GitHub Releases: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64. Cài thêm được bằng `go install`.
- License Apache-2.0.
- README nêu rõ mô hình đe dọa ở 5.3.
