# agentssh GUI — Thiết kế

- Ngày: 2026-11-11
- Trạng thái: chờ review
- Dựa trên: [2026-11-10-agentssh-design.md](2026-11-10-agentssh-design.md) (MVP, đã phát hành v0.1.0)

## 1. Bài toán

Hiện mọi thao tác của người dùng (duyệt lệnh, quản lý host, key, vault, xem log) đều qua CLI. Duyệt lệnh `destructive` phải mở terminal khác, chạy `agentssh approve` rồi gõ mã 4 ký tự từ thông báo desktop. Cách này an toàn nhưng phiền khi dùng hằng ngày.

Mục tiêu: một GUI luôn sẵn sàng để quản lý yêu cầu duyệt, host, vault/key và nhật ký trên Linux, macOS và Windows. GUI không được làm yếu đi mô hình bảo mật của MVP.

## 2. Mục tiêu và ngoài phạm vi

Mục tiêu:

1. Bốn màn hình: Duyệt, Host, Vault & key, Nhật ký & trạng thái (mục 6).
2. Chứng minh "người thật bấm" bằng xác thực của hệ điều hành, thay cho mã 4 ký tự.
3. Có cho cả Linux, macOS và Windows ngay từ bản đầu.
4. Vẫn một binary duy nhất; không có bước build frontend.
5. Icon khay hệ thống luôn bật, hiện số yêu cầu đang chờ; bấm thông báo thì mở thẳng trang duyệt (trừ macOS, xem 7.2).

Ngoài phạm vi:

- Cửa sổ app riêng (webview), chế độ tối/sáng tùy chỉnh, đa ngôn ngữ. Giao diện bản này dùng tiếng Việt.
- Xuất private key qua GUI. Việc này vẫn chỉ làm được qua `agentssh key export` trên terminal.
- Sửa `rules.toml` qua GUI. Người dùng vẫn sửa file rồi bấm Reload.
- Truy cập GUI từ máy khác. UI chỉ lắng nghe trên `127.0.0.1`.

## 3. Kiến trúc

```text
  Trình duyệt (tab agentssh)      Icon khay (số yêu cầu chờ)     Thông báo OS (bấm → trang duyệt)
          │ HTTP 127.0.0.1:<port> + cookie                │
          ▼                                               ▼
  ┌──────────────────────── agentssh daemon ─────────────────────────┐
  │ internal/ui      HTTP server, trang nhúng, SSE                    │
  │ internal/humanok xác thực HĐH: polkit / LocalAuthentication / CredUI │
  │ internal/tray    icon khay (fyne.io/systray)                      │
  │ (đã có)          policy, approval, vault, hosts, sshconn, audit   │
  └──────────────────────────────────────────────────────────────────┘
          ▲ unix socket (không đổi)
   agentssh CLI / MCP / hook
```

| Package | Trách nhiệm |
|---|---|
| `internal/humanok` | `Confirm(ctx, msg string) error`: bật hộp xác thực HĐH, trả `nil` khi người dùng xác thực thành công. Mỗi OS một file, có thêm bản giả chỉ dùng cho test. |
| `internal/ui` | HTTP server: token/cookie, kiểm tra Host/Origin, API JSON, SSE `/events`, file tĩnh nhúng bằng `embed` (HTML + CSS + JS thuần, không dùng framework). |
| `internal/tray` | Icon khay, số yêu cầu chờ, menu. Tự tắt khi không có phiên đồ họa. |

Mọi API của UI gọi lại đúng các hàm daemon đang dùng cho RPC (Decide, Admin, Unlock, Lock, Keys, Hosts, Pending, Status). Tầng cứng không đổi: policy, profile, forbidden và known_hosts vẫn y như cũ.

Dependency mới duy nhất: `fyne.io/systray`. Trên Linux và Windows nó thuần Go (Linux đi qua D-Bus StatusNotifierItem); trên macOS nó cần cgo.

Hệ quả cho việc phát hành: bản macOS phải build trên runner macOS với `CGO_ENABLED=1`, vì icon khay và LocalAuthentication đều cần cgo. Bản Linux và Windows vẫn build chéo được với `CGO_ENABLED=0`.

## 4. Xác thực "người thật bấm"

### 4.1 Nguyên tắc

- Hộp xác thực do **daemon** bật lên, không phải GUI. Bất kể yêu cầu đến từ GUI, CLI hay một agent cố gọi API, daemon đều gọi `humanok.Confirm` trước khi thực hiện. Vì vậy GUI không cần là kênh bí mật: agent mở được UI cũng không duyệt được gì.
- Lời nhắn trong hộp xác thực do daemon tạo từ dữ liệu của chính nó: host, lệnh gốc, mức rủi ro. Không bao giờ dùng mô tả do agent viết.
- Mỗi lần xác thực chỉ có hiệu lực cho đúng một thao tác. Không có kiểu "đã xác thực thì cho qua trong N phút". Ngoại lệ là lựa chọn `s` (cho phép đúng lệnh đó trên đúng host đó trong 30 phút), vẫn giữ như MVP.

### 4.2 Thao tác cần xác thực

| Thao tác | Xác thực |
|---|---|
| Duyệt yêu cầu (`y`, `s`) | Có |
| Từ chối (`n`, `m`) | Không |
| Lệnh `mutate` từ agent không phải Claude Code trên host `standard` | Có (đi qua luồng duyệt) |
| Thêm/sửa/xóa host, trust host key, reload config | Có |
| Tạo/import/xóa key | Có |
| Mở khóa vault | Chế độ keyring: có. Chế độ passphrase: passphrase chính là bằng chứng. |
| Khóa vault | Không |
| Xuất key (CLI) | Có, cộng với passphrase nếu vault ở chế độ passphrase |

### 4.3 Hiện thực theo OS

| OS | Cách làm | Ghi chú |
|---|---|---|
| Linux | `pkcheck --action-id dev.agentssh.confirm --process <pid daemon> --allow-user-interaction --detail message "<lời nhắn>"` | Action `dev.agentssh.confirm` có `allow_active=auth_self`, được cài bằng `sudo agentssh install-polkit`. Agent polkit của desktop sẽ dùng vân tay nếu có fprintd. |
| macOS | LocalAuthentication, `LAPolicyDeviceOwnerAuthentication`, qua cgo | Touch ID, hoặc mật khẩu máy. |
| Windows | `CredUIPromptForWindowsCredentialsW` cho user hiện tại, rồi kiểm tra bằng `LogonUserW` | Gọi syscall qua `x/sys/windows`, không cần cgo. |

### 4.4 Dự phòng

`humanok.Available()` trả về false trong các trường hợp:

- Không có phiên đồ họa.
- Chưa cài polkit action.
- pkcheck báo không có authentication agent.

Khi đó daemon quay về cơ chế mã 4 ký tự gửi qua thông báo desktop, đúng như MVP. `doctor` và màn hình Trạng thái hiện chế độ đang dùng: `xác thực HĐH` hoặc `mã duyệt`.

### 4.5 Rủi ro phải làm thử (spike) đầu tiên

1. **Polkit dưới `systemd --user`:** pkcheck với `--process` là pid daemon có hiện hộp thoại trong phiên đồ họa không, vì session của service có thể không phải session `active`.
   - Nếu không được: cho daemon chạy dưới `graphical-session.target`, hoặc dùng `--system-bus-name` của tiến trình UI/tray.
   - Nếu vẫn không được thì dùng dự phòng mục 4.4 và ghi rõ trong tài liệu.
2. **Lời nhắn polkit có chèn được nội dung lệnh không** (`$(message)` từ `--detail`). Nếu không: hộp thoại hiện câu cố định "agentssh cần xác nhận thao tác #12", còn GUI hiện lệnh đầy đủ ngay cạnh.
3. **Windows Hello PIN:** `LogonUserW` không xác minh được PIN. Nếu CredUI trả về PIN thì dùng `UserConsentVerifier` (WinRT) thay thế, hoặc chỉ chấp nhận mật khẩu Windows. Phải chốt sau khi spike.
4. **macOS:** LocalAuthentication có chạy được từ LaunchAgent không. Nếu không thì để tiến trình tray gọi rồi báo kết quả cho daemon qua socket. Tray chạy trong phiên Aqua, nhưng daemon phải kiểm tra tray đúng là tiến trình con của nó.

## 5. Bảo mật web UI

- **Địa chỉ:** lắng nghe trên `127.0.0.1:0` (cổng ngẫu nhiên). Cổng cố định chỉnh được bằng `agentssh daemon --ui-port`.
- **Token:** mỗi lần khởi động, daemon sinh 32 byte ngẫu nhiên. URL `http://127.0.0.1:<port>/?t=<token>` được ghi vào `<state>/ui.url` với quyền 600.
- **Lần mở đầu:** `GET /?t=<token>` đặt cookie `agentssh` (HttpOnly, SameSite=Strict, Path=/) rồi chuyển hướng 303 về `/` để token không nằm lại trong lịch sử. Request nào không có cookie hợp lệ đều nhận 401.
- **Host header:** phải đúng `127.0.0.1:<port>` hoặc `localhost:<port>`, nếu không thì trả 421. Việc này chống DNS rebinding.
- **POST/PUT/DELETE:** `Origin` phải trùng với origin của UI. Body là JSON, `Content-Type: application/json`. Việc này chống CSRF.
- **Header phản hồi:** `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- **Không có bí mật nào đi qua UI.** UI chỉ hiện public key và fingerprint. Passphrase nhập để mở khóa vault chỉ đi qua loopback và không được lưu.
- **Dữ liệu chỉ đọc** (audit, host, output, yêu cầu chờ): agent vốn đọc được các file này, nên lộ qua UI không thêm rủi ro. Mọi thao tác thay đổi đều qua mục 4.
- **`ui.url` không phải bí mật đối với agent.** Token chỉ chặn user khác trên cùng máy và các trang web lạ.

## 6. Màn hình

Một trang duy nhất có 4 tab, cập nhật trực tiếp qua `GET /events` (SSE, stdlib).

1. **Duyệt**
   - Danh sách yêu cầu chờ, mới nhất ở trên, có đếm ngược tới lúc hết hạn (120 s).
   - Chi tiết: lệnh gốc (dùng `Reasons[].Start/End` để tô đỏ), mức rủi ro, các lý do, host/user, agent, cwd, repo, thời điểm.
   - Nút: **Duyệt 1 lần**, **Duyệt 30 phút** (đúng lệnh, đúng host), **Từ chối**, **Từ chối kèm lời nhắn** (ô nhập).
   - Khi bấm Duyệt, giao diện hiện "Đang chờ xác thực của hệ điều hành…" cho tới khi hộp thoại HĐH trả kết quả.
2. **Host**
   - Bảng gồm: tên, user@host:port, profile, agent bật/tắt, key, trạng thái host key (đã trust / chưa / thay đổi).
   - Form thêm/sửa: host, port, user, key (chọn từ vault), profile, agent, mô tả, allow/deny (mỗi dòng một pattern).
   - Nút **Trust**: daemon lấy host key, hiện fingerprint, người dùng xác thực để chấp nhận.
   - Nút **Xóa**.
   - Nút **Reload** (đọc lại `hosts.toml`/`rules.toml` sau khi sửa tay). Nếu config trên đĩa khác bản đã duyệt, hiện cảnh báo nổi bật.
3. **Vault & key**
   - Trạng thái: khóa/mở, chế độ keyring hoặc passphrase.
   - Nút Khóa/Mở; chế độ passphrase thì có ô nhập passphrase.
   - Danh sách key: tên, loại, fingerprint, hoặc nhãn "mật khẩu".
   - **Tạo key:** hiện public key cùng nút copy và hướng dẫn thêm vào `authorized_keys`.
   - **Import:** tải lên file key (có ô passphrase của key nếu key được mã hóa), hoặc nhập mật khẩu.
   - **Xóa key.**
4. **Nhật ký & trạng thái**
   - Các ô trạng thái:
     - daemon, phiên bản;
     - vault;
     - chế độ xác thực (HĐH hay mã);
     - hook của từng agent (Claude/Codex/Gemini/Antigravity);
     - thông báo desktop;
     - key cá nhân không có passphrase.
   - Bảng audit lọc theo host, quyết định, khoảng thời gian, có phân trang.
   - Bấm một dòng để xem output đầy đủ (`out/<id>`, giữ 7 ngày) và lọc theo regexp.

## 7. Icon khay và thông báo

### 7.1 Icon khay

- Icon cùng số yêu cầu chờ. Tooltip ví dụ "agentssh: 2 yêu cầu chờ duyệt".
- Menu: **Mở agentssh** (mở `ui.url` bằng `xdg-open` / `open` / `rundll32 url.dll`), **Khóa vault**, **Ẩn icon** (cho tới lần khởi động sau).
- Linux GNOME cần extension AppIndicator; Ubuntu cài sẵn, các bản khác thì `doctor` báo nếu thiếu.
- `agentssh daemon --no-tray` tắt icon. Không có phiên đồ họa thì icon tự tắt.

### 7.2 Thông báo bấm được

| OS | Cách làm |
|---|---|
| Linux | `notify-send -A open=Mở --wait …` chạy trong goroutine; nếu nhận `open` thì mở `ui.url#req=<id>`. |
| Windows | Toast có `activationType="protocol"` và `launch="<ui.url>#req=<id>"`. |
| macOS | `osascript` không hỗ trợ bấm; dùng icon khay. |

Khi xác thực HĐH đang hoạt động, nội dung thông báo không còn mã duyệt, ví dụ: "VMT_DWH: rm -rf /var/log/old [destructive], bấm để duyệt".

## 8. Thay đổi với CLI và daemon hiện có

- `agentssh approve`: khi `humanok.Available()`, lệnh không hỏi mã nữa. Chọn `y`/`s` sẽ bật hộp xác thực HĐH. Ngược lại vẫn hỏi mã như cũ.
- Các lệnh quản trị trên CLI (`host`, `key`, `reload`, `trust`) cũng chuyển sang xác thực HĐH theo cùng quy tắc. Chúng vẫn bắt chạy trên terminal thật.
- `agentssh daemon` thêm cờ `--no-ui`, `--no-tray`, `--ui-port N`.
- Lệnh mới `agentssh ui` mở trình duyệt vào `ui.url`.
- Lệnh mới `sudo agentssh install-polkit` cài file `/usr/share/polkit-1/actions/dev.agentssh.policy`.
- `doctor` kiểm tra thêm: chế độ xác thực, polkit action, UI đang lắng nghe, icon khay.
- Audit: trường `code_ok` vẫn giữ; thêm `auth: "os"|"code"|"passphrase"`.

## 9. Kiểm thử

- `internal/ui` test bằng `httptest`:
  - token đổi thành cookie, thiếu cookie bị 401;
  - Host sai bị 421;
  - Origin sai bị 403;
  - từng endpoint với `humanok` giả (luôn chấp nhận / luôn từ chối);
  - SSE gửi sự kiện khi có yêu cầu mới.
- `internal/humanok`: test interface và đường dự phòng (`Available()` false thì dùng mã). Hộp thoại thật của HĐH không tự động hóa được.
- E2E (`scripts/e2e.py`): build với tag `e2efake`, để `humanok` đọc quyết định từ file do test ghi. Kịch bản: duyệt qua API của UI, các thao tác host/key qua UI, kiểm tra token/Host/Origin trên binary thật. Bản phát hành không bao giờ có tag này.
- CI: unit test trên 3 OS như hiện nay; thêm một bước build macOS với cgo.
- Checklist test tay cho từng OS, chạy trước mỗi lần phát hành:
  - hộp xác thực hiện đúng lời nhắn;
  - vân tay/Touch ID/PIN;
  - từ chối xác thực thì thao tác bị hủy;
  - icon khay và số yêu cầu chờ;
  - bấm thông báo mở đúng yêu cầu;
  - chế độ dự phòng khi ssh vào máy.

## 10. Thứ tự triển khai

1. Spike mục 4.5 trên Linux (polkit + systemd --user), rồi macOS, rồi Windows. Ghi kết quả vào spec này.
2. `internal/humanok` cho 3 OS, cùng `install-polkit`.
3. Đưa xác thực HĐH vào daemon thay mã (mã thành dự phòng); cập nhật CLI `approve` và các lệnh quản trị.
4. `internal/ui`: server, bảo mật, API, SSE và 4 màn hình.
5. `internal/tray` và thông báo bấm được.
6. `doctor`, README (mô hình đe dọa cập nhật theo mục 4), CI macOS cgo, phát hành v0.2.0.
