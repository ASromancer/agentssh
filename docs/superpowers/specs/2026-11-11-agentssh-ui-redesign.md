# agentssh UI — Thiết kế lại giao diện

- Ngày: 2026-11-11
- Trạng thái: người dùng giao toàn quyền ("cứ làm đi, sao cho đẹp nhất")
- Dựa trên: [2026-11-11-agentssh-gui-design.md](2026-11-11-agentssh-gui-design.md) §5–7. API và bảo mật giữ nguyên.

## 1. Mục tiêu

Trang quản lý hiện chạy đúng nhưng trông sơ sài: CSS chỉ khoảng 40 dòng và dùng `confirm`/`prompt` của trình duyệt. Bản mới phải có chất lượng tương đương một sản phẩm devtool hiện đại (Linear, Vercel, Tailscale admin), nhưng vẫn giữ các ràng buộc:

- **JS thuần, không framework, không bước build, không CDN, không phụ thuộc mới.** React và các framework tương tự bị loại vì cần npm/bundler và kéo theo rủi ro chuỗi cung ứng.
- **CSP `default-src 'self'` giữ nguyên:**
  - không inline `<script>`/`<style>`, không thuộc tính `style=` hay `on*=`;
  - không dùng `innerHTML`; icon SVG tạo bằng `createElementNS`.
- **Chữ do agent gửi tới** (lệnh, ghi chú, tên host) **chỉ được đưa vào trang bằng `textContent`**.
- Giao diện tiếng Việt; font hệ thống, không tải font ngoài.
- Server chỉ phục vụ đúng các file có trong danh sách. Thêm file mới thì phải đăng ký vào danh sách đó.

## 2. Ngôn ngữ thiết kế

- **Phong cách:** "ops console" tối giản, mặc định theo chế độ sáng/tối của hệ thống, có nút chuyển theme (lưu trong `localStorage`).
- **Token CSS** (biến `--…`):
  - nền, bề mặt 1/2/3, viền, chữ chính/phụ/mờ;
  - màu nhấn (xanh dương), thành công, cảnh báo, nguy hiểm;
  - bo góc 6/10/14px, bóng đổ 2 cấp;
  - khoảng cách theo bội số 4px;
  - cỡ chữ 12/13/14/16/20/28.
- **Màu theo mức rủi ro:**

  | Mức | Màu |
  |---|---|
  | read | xám |
  | mutate | hổ phách |
  | destructive | đỏ |
  | forbidden | tím đậm |

  Dùng thống nhất cho mọi pill, badge và vạch đánh dấu.
- **Chuyển động:** 120–180 ms ease-out cho hover, mở/đóng drawer và modal, toast. Tôn trọng `prefers-reduced-motion`.
- **Truy cập:** focus ring rõ ràng; nút có nhãn; toast dùng `aria-live`; modal bẫy focus và đóng được bằng Esc; độ tương phản đạt AA.

## 3. Bố cục

- **Sidebar trái** (thu gọn thành thanh trên khi màn hẹp hơn 860px):
  - logo agentssh;
  - 4 mục điều hướng có icon: Duyệt (badge số đỏ), Host, Vault & key, Nhật ký;
  - đáy sidebar: chấm trạng thái kết nối SSE (xanh/đỏ) và phiên bản.
- **Thanh trên:**
  - tiêu đề màn hình;
  - các chip trạng thái: "Xác thực hệ điều hành" hoặc "Mã duyệt"; vault mở/khóa, bấm vào để mở/khóa;
  - nút đổi theme.
- **Banner cảnh báo** khi config trên đĩa chưa được duyệt (UserOnly), dính ở đầu nội dung.
- **Toast** thay cho thanh flash: xếp chồng ở góc dưới phải, tự ẩn; lỗi có nút đóng.
- **Modal tự làm** thay `confirm()`/`prompt()`: xác nhận xóa, nhập mã duyệt (chế độ mã), xác nhận fingerprint host key.
- **Drawer phải:** form thêm/sửa host, xem output lệnh.

## 4. Các màn hình

1. **Duyệt**
   - Mỗi yêu cầu là một card lớn:
     - **Hàng đầu:** pill mức rủi ro, `#id`, host, agent, thời gian tương đối ("12 giây trước").
     - **Đếm ngược:** thanh tiến độ mỏng chạy theo `expires`.
     - **Khối lệnh:** monospace, nền tối, nút copy; phần nguy hiểm gạch chân đỏ, đặt vị trí theo byte offset như hiện tại.
     - **Lý do:** danh sách có icon theo mức.
     - **Metadata thu gọn:** user, cwd, repo, loại.
     - **Nút:** "Duyệt 1 lần" (chính), "Duyệt 30 phút", "Từ chối"; "Từ chối kèm lời nhắn" mở ô nhập ngay trong card.
     - **Khi đang chờ xác thực HĐH:** nút có spinner và dòng "Đang chờ xác thực trên hệ điều hành…".
   - Card có `#req=N` được làm nổi bật và cuộn tới.
   - **Trạng thái rỗng:** minh họa SVG cùng dòng "Không có yêu cầu nào đang chờ" và gợi ý ngắn.
2. **Host**
   - Ô tìm kiếm và nút "Thêm host".
   - Mỗi host là một hàng hoặc card:
     - tên, `user@host:port`;
     - pill profile, chấm "agent" bật/tắt, key;
     - trạng thái host key: đã tin (xanh) hoặc chưa tin (hổ phách);
     - menu hành động: Sửa, Trust, Xóa.
   - **Drawer form:**
     - các trường có nhãn và mô tả ngắn;
     - profile chọn bằng segmented control;
     - agent là một toggle;
     - allow/deny là ô nhập dạng chip, Enter để thêm;
     - kiểm tra dữ liệu tại chỗ.
   - Nút "Đọc lại cấu hình" ở thanh công cụ.
3. **Vault & key**
   - **Thẻ trạng thái lớn:** icon khóa, "Đang mở"/"Đang khóa", chế độ keyring hoặc passphrase, nút Khóa/Mở (ô passphrase khi cần).
   - **Danh sách key:** tên, loại, fingerprint rút gọn có nút copy, nút xóa.
   - **Ba hành động:** Tạo key, Import key, Lưu mật khẩu, mỗi cái mở một modal.
   - **Sau khi tạo key:** public key hiện trong khối có nút copy, kèm hướng dẫn thêm vào `authorized_keys`.
4. **Nhật ký & trạng thái**
   - **Lưới "Sức khỏe":** các thẻ nhỏ từ `/api/doctor`, xanh hoặc cảnh báo.
   - **Thanh lọc:** host, quyết định (segmented hoặc select), từ ngày.
   - **Bảng audit:**
     - header dính khi cuộn, hàng zebra nhẹ;
     - badge mức và quyết định, exit code tô màu (0 xanh, khác 0 đỏ);
     - phân trang.
   - **Xem output:** bấm một hàng để mở drawer, có ô lọc regexp và nút copy.

## 5. Thay đổi phía Go (nhỏ)

- `approval.Request` thêm trường `Expires time.Time` (`json:"expires"`), đặt trong `Queue.Add` bằng thời điểm tạo cộng `Queue.Timeout`, để giao diện vẽ được đếm ngược. Mục này nằm trong danh sách hoãn ở §11 của spec GUI.
- Thêm test kiểm tra `expires` được trả về đúng.
- Nếu tách JS hoặc CSS thành nhiều file, hoặc thêm file `icons.svg`, phải thêm tên file vào danh sách file trong `internal/ui/server.go`, kèm Content-Type đúng.

## 6. Kiểm thử

- Cập nhật `static_test.go`:
  - không có inline script/style/handler;
  - không dùng `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`;
  - có đủ 4 màn hình (`data-view="approvals|hosts|vault|log"`);
  - JS gọi đủ các endpoint.
- Giữ `node --check` và `internal/ui/testdata/highlight_test.mjs` (hàm đổi byte offset vẫn export như cũ).
- E2E không đổi, vì chỉ dùng API.
- Kiểm thử tay: người dùng mở `agentssh ui`, xem cả hai theme, bản hẹp và rộng, duyệt một yêu cầu.

## 7. Ngoài phạm vi

- i18n nhiều ngôn ngữ, phím tắt để duyệt (cố ý không có, để tránh duyệt nhầm), biểu đồ thống kê.

## 8. Bổ sung (2026-11-11): tham khảo các mẫu UX của Termius

Chỉ học mẫu tương tác, không sao chép nhận diện, logo hay màu thương hiệu.

- **Host dạng lưới card** (`repeat(auto-fill, minmax(260px, 1fr))`).
  - Mỗi card có:
    - ô avatar bo góc, màu sinh từ hash của tên, hiện 2 chữ cái đầu;
    - tên, `user@host:port`;
    - các pill profile, agent và host key;
    - menu "…" gồm Sửa, Trust, Copy `user@host`, Xóa.
  - Bấm vào card thì mở drawer sửa.
  - Thanh tìm kiếm luôn ở đầu, lọc theo tên, địa chỉ và mô tả.
  - Hai nhóm "Agent dùng được" và "Ẩn với agent".
  - Nút chuyển lưới/danh sách, lưu vào `localStorage`.
- **Tab "Kho khóa"** thay cho "Vault & key".
  - Đầu tab là thẻ trạng thái vault.
  - Mục **Key:** loại, fingerprint rút gọn có nút copy, dòng "Đang dùng bởi: web1, db" tính ở phía client từ `hosts.key`, và nút xóa.
  - Mục **Mật khẩu:** liệt kê riêng.
  - Ba hành động mở modal: Tạo key, Import key, Lưu mật khẩu.
- **Tab mới "Known hosts":**
  - Endpoint chỉ đọc `GET /api/knownhosts` trả về `[{host, type, fingerprint}]`, đọc từ `paths.KnownHosts()` bằng `ssh.ParseKnownHosts`.
  - known_hosts không chứa bí mật nên được phép đọc.
  - Hiện thêm tên host agentssh tương ứng (khớp `Addr()`) và nút "Trust lại", gọi đúng luồng `trust` hiện có.
  - Có test cho endpoint.
- **Responsive:**
  - **từ 860px trở lên:** có sidebar;
  - **640–860px:** thanh điều hướng trên;
  - **dưới 640px:** thanh tab cố định ở đáy với icon và nhãn ngắn, đáy chừa khoảng an toàn bằng `env(safe-area-inset-bottom)`.

  Drawer và modal chiếm toàn màn hình khi hẹp hơn 640px, và mọi vùng bấm có kích thước tối thiểu 40px.
- `data-view` gồm: `approvals | hosts | keychain | knownhosts | log`. Test tĩnh cập nhật theo.
