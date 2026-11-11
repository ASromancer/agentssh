# Ostiary — đổi tên, nhận diện, đóng gói app, nâng cấp, phát hành

- Ngày: 2026-11-11
- Trạng thái: người dùng giao quyền quyết định ("cứ làm thôi"). Hai điểm đã chốt cùng người dùng: tên **Ostiary**; **cắt hẳn** khỏi agentssh.
- Dựa trên: [2026-11-10-agentssh-design.md](2026-11-10-agentssh-design.md), [2026-11-11-agentssh-gui-design.md](2026-11-11-agentssh-gui-design.md), [2026-11-11-agentssh-ui-redesign.md](2026-11-11-agentssh-ui-redesign.md). Mô hình bảo mật giữ nguyên.

## 1. Mục tiêu và thứ tự

Biến agentssh thành một sản phẩm người khác tải về là dùng được:

- bấm vào app thì mở được giao diện, không cần gõ lệnh;
- lần đầu có hướng dẫn từng bước;
- có bản nâng cấp an toàn;
- có tên và nhận diện riêng.

Công việc chia thành 5 giai đoạn. Mỗi giai đoạn có plan riêng, làm theo đúng thứ tự dưới đây.

| # | Giai đoạn | Kết quả |
|---|---|---|
| P0 | Gộp nhánh hiện có | PR #1 rồi PR #2 merge vào `main` (CI xanh). Nhánh mới `feat/ostiary` tách từ `main`. |
| P1 | Đổi tên + nhận diện | Mọi định danh thành `ostiary`, có logo, icon và bảng màu. |
| P2 | Rà UX/UI + onboarding | Màn hình "Bắt đầu" cho lần chạy đầu, sửa các lỗi tìm được khi rà. |
| P3 | App cho 3 hệ điều hành | Lệnh `ostiary open`. Windows: bộ cài `.exe`. macOS: `.app` trong `.dmg`. Linux: `.deb` và mục trong menu ứng dụng. |
| P4 | Nâng cấp | Bản phát hành có chữ ký. Có `ostiary upgrade`, và daemon tự kiểm tra bản mới rồi báo trên UI. |
| P5 | Phát hành | Đổi tên repo GitHub, merge `feat/ostiary`, tag `v0.2.0`. |

## 2. Tên và nhận diện

- **Tên:** Ostiary, nghĩa là người giữ cửa đền. Lệnh gõ: `ostiary`.
- **Slogan:**
  - EN: "The doorkeeper between AI agents and your servers."
  - VI: "Người gác cửa giữa AI agent và máy chủ của bạn."
- **Biểu tượng:** khung cửa vòm (hình chữ nhật, đỉnh bo tròn), giữa có lỗ khóa (hình tròn cộng hình thang).
  - Chỉ dùng hình hình học, nét đều.
  - Phải còn đọc được ở 16px: ở cỡ nhỏ bỏ nét viền trong, chỉ giữ khối cửa và lỗ khóa.
- **Màu:**
  - Màu chính **teal**: `#0D9488` cho nền sáng, `#2DD4BF` cho nền tối.
  - Nền icon app: gradient từ `#0F766E` sang `#134E4A`, lỗ khóa màu `#F0FDFA`.
  - Teal không trùng với 4 màu mức rủi ro (xám, hổ phách, đỏ, tím). Vì vậy màu nhấn (`--accent`) của UI chuyển từ xanh dương sang teal.
- **Chữ:** dùng font hệ thống như cũ. Wordmark là chữ "Ostiary" đậm 600, giãn chữ -0.01em, đặt cạnh biểu tượng.
- **File nguồn** đặt trong `assets/brand/`:
  - `mark.svg`: biểu tượng, nền trong suốt, dùng `currentColor`;
  - `app-icon.svg`: ô bo góc kèm gradient;
  - `tray.svg`: biểu tượng đơn sắc cho khay hệ thống;
  - `README.md`: quy tắc dùng (khoảng trống quanh logo, màu, cỡ tối thiểu).
- **File sinh ra từ nguồn** (được commit để CI không cần công cụ vẽ):
  - PNG các cỡ 16, 32, 48, 64, 128, 256, 512, 1024;
  - `ostiary.ico` (chứa PNG);
  - `ostiary.icns` (các loại ic07 đến ic10, chứa PNG);
  - favicon cho UI;
  - icon khay (thay `internal/tray/icon.go`).
- **Cách sinh:** dùng `tools/brandgen`.
  - Bước 1, chạy tay: vẽ SVG ra PNG bằng Chrome headless.
  - Bước 2, bằng Go thuần, có test: đóng gói PNG thành ICO/ICNS.

## 3. Đổi tên (cắt hẳn)

Ostiary là app mới. Nó không đọc, không chuyển, không xóa bất cứ dữ liệu nào của agentssh.

| Cũ | Mới |
|---|---|
| module `github.com/ASromancer/agentssh` | `github.com/ASromancer/ostiary` |
| binary `agentssh` | `ostiary` (thêm `ostiary-app.exe` trên Windows, xem §5) |
| `~/.config/agentssh`, state, socket `agentssh.sock` | `ostiary`, `ostiary.sock` |
| keyring service/user | `ostiary` |
| biến môi trường `AGENTSSH_*` (kể cả `AGENTSSH_E2E_*`) | `OSTIARY_*` |
| systemd unit `agentssh.service`, launchd `dev.agentssh`, schtasks `agentssh` | `ostiary.service`, `dev.ostiary`, `ostiary` |
| polkit action `…agentssh…` | đổi theo tên mới |
| hook `agentssh hook <agent>`, skill/plugin/MCP `agentssh` | `ostiary …` |
| luật chặn đường dẫn nhạy cảm trong `policy` và `hook` (config, vault, service) | trỏ sang đường dẫn và tên của ostiary |
| danh sách lệnh chỉ người dùng được chạy (`humanOnly`) trong hook | thêm `open`, `upgrade`, `uninstall-service` |

**Hướng dẫn trong README cho người đang dùng agentssh:**

1. Gỡ hook cũ: xóa các mục `agentssh hook` trong settings của từng agent.
2. Tắt service cũ.
3. Cài Ostiary, `init`, thêm lại host và key.

**Không làm** lệnh tự gỡ agentssh. Lý do: người dùng chọn cắt hẳn, và số người đang dùng còn ít.

**Kiểm tra sau khi đổi tên:**

- `grep -ri agentssh` chỉ còn khớp trong `docs/` (lịch sử) và mục hướng dẫn chuyển ở README;
- CI có bước kiểm tra binary phát hành không chứa `OSTIARY_E2E`.

## 4. Rà UX/UI và màn hình "Bắt đầu"

### 4.1 Onboarding (bắt buộc)

Với cách cắt hẳn, mọi người dùng, kể cả bạn, đều bắt đầu từ con số 0. Vì vậy UI phải tự dẫn người dùng đi qua lần đầu.

**Điều kiện hiện:** `Status` trả về `Initialized` (vault đã tồn tại hay chưa) và `Setup` (danh sách bước đã xong). Khi vault chưa có, hoặc còn bước chưa xong mà người dùng chưa bấm "Bỏ qua", UI hiện màn hình **Bắt đầu** thay cho màn Duyệt. Có thể mở lại màn này từ menu.

**Các bước:**

1. **Tạo vault.**
   - Nút "Tạo vault" dùng OS keyring. Lựa chọn phụ "Dùng passphrase" có ô nhập 2 lần, tối thiểu 8 ký tự.
   - Thao tác admin mới `init` đi qua Begin/Admin như các thao tác khác. Khi vault chưa có, không có gì để mất, nhưng vẫn yêu cầu xác thực HĐH hoặc mã duyệt, cho thống nhất và để agent không tạo vault thay người dùng.
2. **Thêm host đầu tiên.** Mở lại drawer "Thêm host" có sẵn. Sau khi lưu thì gợi ý luôn "Trust host key".
3. **Thêm key hoặc mật khẩu.** Dùng lại các modal Tạo key / Import key / Lưu mật khẩu. Sau khi tạo key thì hiện public key kèm lệnh thêm vào `authorized_keys`.
4. **Kết nối agent.**
   - Liệt kê các agent phát hiện được (Claude Code, Codex, Gemini CLI, Antigravity), dùng logic phát hiện sẵn có của `install-hooks`.
   - Mỗi agent có nút "Cài", gọi thao tác admin mới `hooks` (tham số: tên agent). Thao tác này dùng chung code với `install-hooks` và vẫn chỉ người dùng mới làm được.
5. **Tự chạy khi đăng nhập.**
   - Toggle bật/tắt, gọi thao tác admin `autostart` (on/off), dùng lại `installService`.
   - Thêm hàm `removeService` để tắt.
6. **(Chỉ Linux) Xác thực hệ điều hành.** Nếu polkit chưa cài thì hiện lệnh để copy: `sudo "$(command -v ostiary)" install-polkit` (lệnh này cần sudo, UI không chạy thay).

**Trạng thái bước** được lưu ở `state/setup.json`, gồm các bước đã xong và cờ "Bỏ qua". Các bước 1–5 được suy ra từ trạng thái thật (có vault, có host, có key, hook đã cài, service đã cài). File chỉ cần lưu cờ "Bỏ qua".

### 4.2 Rà tổng thể

Một reviewer rà toàn bộ UI theo danh sách kiểm sau và ghi các phát hiện ra file:

- heuristics của Nielsen;
- trạng thái rỗng, đang tải, lỗi trên mọi màn;
- câu chữ tiếng Việt nhất quán, không còn tiếng Anh lẫn vào, trừ thuật ngữ như host key hay fingerprint;
- thông báo lỗi từ daemon (tiếng Anh) được dịch hoặc diễn giải ở các lỗi hay gặp:
  - ticket hết hạn;
  - sai mã;
  - vault đang khóa;
  - không kết nối được host;
- bàn phím và focus;
- 3 kích thước màn hình × 2 theme;
- thao tác có thể làm hỏng dữ liệu phải có xác nhận;
- đường đi ngắn nhất cho 5 việc thường làm: duyệt, thêm host, trust, thêm key, xem output.

Phát hiện mức Critical và Important phải sửa trong P2. Mức Minor sửa nếu rẻ, còn lại ghi vào ledger.

## 5. App cho từng hệ điều hành

### 5.1 `ostiary open`

Lệnh `ostiary open` là điểm vào của mọi icon app:

1. Nếu daemon chưa chạy:
   - đã cài service: khởi động qua service (`systemctl --user start ostiary`, `launchctl kickstart`, hoặc `schtasks /Run`);
   - chưa cài service: chạy `daemon --detach`.
2. Chờ socket tối đa 5 giây, dùng `dialRetry`.
3. Gọi `UILogin` để lấy link đăng nhập, rồi mở trình duyệt. Nếu vault chưa có, UI tự hiện màn Bắt đầu.
4. Lỗi được báo bằng thông báo hệ thống, vì icon app không có terminal. Riêng trường hợp chạy trong terminal thì in ra stderr.

### 5.2 Windows

- **Hai file chạy cùng mã nguồn:**
  - `ostiary.exe`: bản console, dùng cho CLI và hook;
  - `ostiary-app.exe`: build với `-ldflags -H=windowsgui`, nên không hiện cửa sổ console. Chạy không tham số thì tương đương `open`. Daemon detach cũng được khởi động bằng file này.
- **Bộ cài `Ostiary-Setup-<ver>-<arch>.exe`:** dùng Inno Setup 6, có sẵn trên runner `windows-latest` (lệnh `iscc`).
  - Cài cho một người dùng, không cần quyền admin, vào `%LOCALAPPDATA%\Programs\Ostiary`.
  - Thêm thư mục vào PATH của người dùng (HKCU).
  - Shortcut "Ostiary" trong Start Menu, tùy chọn thêm shortcut ngoài Desktop.
  - Ô chọn "Chạy khi đăng nhập", mặc định bật, chạy `ostiary install-service`.
  - Trang cuối có "Mở Ostiary".
  - Có Uninstaller, chạy `ostiary uninstall-service` trước khi xóa file.
- **Script:** `packaging/windows/ostiary.iss`, có icon `ostiary.ico`.

### 5.3 macOS

- **Bundle `Ostiary.app`:**
  - `Contents/MacOS/ostiary` là binary universal, ghép bằng `lipo` từ bản amd64 và arm64 build bằng cgo.
  - `Contents/MacOS/Ostiary` là script launcher: `exec "$(dirname "$0")/ostiary" open`.
  - `Info.plist`:
    - `CFBundleIdentifier=dev.ostiary.app`;
    - `LSUIElement=true`: không có icon ở Dock, chỉ có icon khay;
    - `CFBundleIconFile=ostiary`.
  - `Contents/Resources/ostiary.icns`.
- **Đóng gói:** `Ostiary-<ver>.dmg` tạo bằng `hdiutil`, bên trong có bản app và một link tới `/Applications`.
- **Chưa ký, chưa notarize** (cần tài khoản Apple Developer). README hướng dẫn lần đầu bấm chuột phải rồi chọn Open, hoặc chạy `xattr -dr com.apple.quarantine`.
- **Lệnh CLI cho agent:** màn Bắt đầu trên macOS hiện lệnh để copy, `sudo ln -sf /Applications/Ostiary.app/Contents/MacOS/ostiary /usr/local/bin/ostiary`. Hook vẫn dùng đường dẫn tuyệt đối của binary nên không cần link này.

### 5.4 Linux

- **Gói `ostiary_<ver>_<arch>.deb`:** tạo bằng nfpm (cài trong CI bằng `go install`, chỉ dùng lúc build). Gói gồm:
  - `/usr/bin/ostiary`;
  - `/usr/share/applications/ostiary.desktop` (`Exec=ostiary open`, `Icon=ostiary`, `Categories=Utility;Security;`);
  - icon trong `/usr/share/icons/hicolor/<n>x<n>/apps/ostiary.png`;
  - `/usr/lib/systemd/user/ostiary.service`.

  Gói không kèm policy polkit, vì annotation owner phải là đúng người dùng. Màn Bắt đầu sẽ hiện lệnh cài.
- **Bản `.tar.gz`:** `ostiary install-service` trên Linux ghi thêm `~/.local/share/applications/ostiary.desktop` và icon vào `~/.local/share/icons/hicolor/…`. Từ đó app hiện trong menu ứng dụng mà không cần gõ `ostiary ui`.
- **Icon:** được nhúng vào binary bằng `embed` để `install-service` ghi ra được.

## 6. Nâng cấp

### 6.1 Chữ ký bản phát hành

- **Khóa ký:** khóa ed25519.
  - Khóa bí mật nằm trong GitHub secret `OSTIARY_SIGNING_KEY`. Bản dự phòng ở `~/.config/ostiary-release/signing.key` (quyền 0600); người dùng nên cất thêm một bản offline.
  - Khóa công khai được nhúng vào binary trong `internal/update/pubkey.go`.
- **Trong CI:** job release tạo `SHA256SUMS`, rồi ký thành `SHA256SUMS.sig` (base64 của chữ ký ed25519 trên đúng các byte của file).
- **Công cụ ký:** `tools/sign`, Go thuần.

### 6.2 `ostiary upgrade [--check]`

1. Gọi `GET https://api.github.com/repos/ASromancer/ostiary/releases/latest`, có timeout 15 giây và User-Agent `ostiary/<ver>`.
2. So phiên bản theo semver. Không mới hơn thì báo "đang dùng bản mới nhất". Có `--check` thì dừng ở bước này.
3. Tải `SHA256SUMS` và `SHA256SUMS.sig`, kiểm chữ ký bằng khóa đã nhúng. Sai chữ ký thì dừng lại và báo lỗi. **Không có chế độ bỏ qua.**
4. Chọn file tải theo cách cài:

   | Cách cài | Nhận biết | Làm gì |
   |---|---|---|
   | Bộ cài Windows | có `ostiary-app.exe` cạnh binary, thư mục nằm trong `%LOCALAPPDATA%\Programs\Ostiary` | Tải Setup.exe, kiểm SHA256, chạy `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`. |
   | `.app` macOS | binary nằm trong `*.app/Contents/MacOS` | Tải binary darwin universal, thay `Contents/MacOS/ostiary`. |
   | `.deb` | binary là `/usr/bin/ostiary` | Không tự thay. Báo lệnh cần chạy: `sudo apt install ./ostiary_<ver>_<arch>.deb`, kèm link tải. |
   | File chạy rời | các trường hợp còn lại | Tải binary đúng OS/arch, kiểm SHA256, ghi ra file tạm cùng thư mục, rồi rename đè lên. Windows: đổi tên file đang chạy thành `.old` trước, lần chạy sau thì xóa. |
5. Khởi động lại daemon nếu nó đang chạy (xem §6.3).

### 6.3 Khởi động lại daemon sau khi nâng cấp

- **Chạy dưới systemd hoặc launchd** (systemd đặt biến `INVOCATION_ID`; với launchd có `KeepAlive`): daemon thoát với mã 75 và service manager tự chạy lại. Với systemd, unit cần `Restart=on-failure`; mã 75 khác 0 nên được tính là failure.
- **Các trường hợp còn lại** (Windows, chạy detach bằng tay): daemon khởi động tiến trình kế nhiệm `ostiary daemon --detach --after-pid <pid>`. Tiến trình mới chờ tiến trình cũ thoát (tối đa 10 giây) rồi mới listen. Sau đó tiến trình cũ thoát.
- **Khi vault dùng passphrase:** sau khi khởi động lại, người dùng phải mở khóa lại. UI hiện việc này sẵn qua chip vault.

### 6.4 Báo có bản mới trên UI

- Daemon kiểm tra bản mới 1 lần sau khi khởi động 1 phút, sau đó cứ 24 giờ một lần.
- Chỉ gọi endpoint "latest release" ở trên, không gửi dữ liệu gì khác.
- Tắt được bằng `OSTIARY_NO_UPDATE_CHECK=1`.
- Kết quả trả qua `Status.Update` gồm `{Version, URL, Notes}`. UI hiện banner "Có bản Ostiary <ver>", với nút "Cập nhật" (thao tác admin `upgrade`) và nút "Xem thay đổi".
- Bản `.deb` thì banner hiện lệnh cài thay cho nút.

## 7. CI và tài sản phát hành

**Job:**

1. `test`: giữ nguyên, đổi tên biến môi trường.
2. `build-unix-windows`: build binary linux và windows (cả `ostiary-app.exe`), rồi đóng `.deb` bằng nfpm.
3. `build-macos`: build bản cgo cho 2 kiến trúc, ghép bằng `lipo`, tạo `.app` rồi `.dmg`.
4. `build-windows-installer`: chạy trên `windows-latest`, `iscc` tạo Setup.exe cho amd64. arm64 dùng bản cài amd64 qua giả lập (emulation); các file chạy rời arm64 vẫn có.
5. `release`: tạo `SHA256SUMS`, ký, upload.

**File trong một bản phát hành:**

- `ostiary-linux-{amd64,arm64}.tar.gz`
- `ostiary_<ver>_{amd64,arm64}.deb`
- `ostiary-windows-{amd64,arm64}.zip` (chứa 2 exe)
- `Ostiary-Setup-<ver>-x64.exe`
- `Ostiary-<ver>.dmg`
- `ostiary-darwin-universal.tar.gz`
- `SHA256SUMS`, `SHA256SUMS.sig`

Kiểm tra "không có hook e2e" chạy trên mọi binary.

## 8. Phát hành (P5)

1. Đổi tên repo GitHub `ASromancer/agentssh` thành `ASromancer/ostiary` qua API. GitHub tự chuyển hướng link cũ. Remote ở máy được cập nhật theo.
2. Cập nhật `.claude-plugin/marketplace.json` và plugin sang tên mới.
3. Merge `feat/ostiary` vào `main`, CI xanh, tag `v0.2.0`.
4. Chạy thử trên máy người dùng (Linux): cài `.deb` hoặc chạy `install-service`, mở app từ menu, đi hết màn Bắt đầu, thêm lại VMT_DWH.
5. Mọi commit và push chỉ dùng danh tính ASromancer.

## 9. Kiểm thử

- **Unit test:**
  - `brandgen` đóng gói ICO/ICNS (kiểm header, số ảnh);
  - `update` kiểm chữ ký (đúng, sai, thiếu), so semver, chọn file tải theo cách cài, thay file tại chỗ (trên thư mục tạm);
  - setup state;
  - các thao tác admin mới `init`, `hooks`, `autostart`, `upgrade` qua Begin/Admin, có test daemon;
  - `open` khi daemon chưa chạy (giả lập).
- **E2E:** đổi tên, giữ đủ 70 kiểm tra. Thêm:
  - `upgrade --check` với một server release giả (`OSTIARY_E2E_RELEASES_URL`, chỉ có trong build `e2efake`);
  - thao tác `init` từ UI (bằng HTTP).
- **CI:** chạy trên 3 hệ điều hành. Có bước kiểm cấu trúc gói:
  - `.deb` bằng `dpkg-deb -c`;
  - `.dmg` mount được và có `Ostiary.app`;
  - Setup.exe chạy `/VERYSILENT` vào thư mục tạm trên runner Windows, rồi `ostiary version`.
- **Kiểm thử tay của người dùng:**
  - Linux: menu ứng dụng, khay, màn Bắt đầu, nâng cấp từ bản build trước lên bản mới.
  - Windows và macOS: kiểm khi có máy.

## 10. Ngoài phạm vi

- Ký code bằng chứng thư (Apple notarization, Windows Authenticode). Cả hai tốn phí, ghi lại để làm sau.
- Homebrew tap, winget, kho apt riêng.
- Tự nâng cấp ngầm không cần hỏi: người dùng luôn phải bấm "Cập nhật".
- Bộ cài MSI.
- Tự gỡ agentssh.
