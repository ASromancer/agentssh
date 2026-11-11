// Run: node internal/ui/testdata/errors_test.mjs  (not part of go test)
import { readFileSync } from "node:fs";
import assert from "node:assert";
const src = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const blk = src.match(/\/\/ ---- errors:begin[\s\S]*?\/\/ ---- errors:end/)[0];
const { friendlyError, reasonVi } = new Function(blk + "\n; return { friendlyError, reasonVi };")();
const errs = [
  ["approval ticket expired or invalid; start again", "Phiếu duyệt đã hết hạn. Hãy thao tác lại."],
  ["bad code: 2 tries left", "Sai mã duyệt (còn 2 lần thử)."],
  ["bad code: request denied after 3 wrong codes", "Sai mã 3 lần: yêu cầu đã bị từ chối."],
  ["vault is locked; run 'ostiary unlock' first", "Vault đang khóa. Mở khóa ở chip Vault trên cùng rồi thử lại."],
  ["dial tcp 10.0.0.5:22: connect: connection refused", "Không kết nối được host (connection refused)."],
  ["dial tcp 10.0.0.5:22: i/o timeout", "Không kết nối được host (hết thời gian chờ)."],
  ["fetch host key from web1:22: dial tcp 10.0.0.5:22: i/o timeout", "Không kết nối được tới web1:22 (hết thời gian chờ)."],
  ["hosts.toml or rules.toml changed on disk; review the change and run 'ostiary reload' first", "Cấu hình trên đĩa đã đổi. Kiểm tra rồi bấm \"Đọc lại cấu hình\" ở màn Host."],
  ["not confirmed by the user: confirmation dialog timed out or was interrupted", "Bạn chưa xác nhận (hoặc đã hủy) trên hộp thoại hệ điều hành."],
  ["no pending request #4", "Yêu cầu #4 đã hết hạn hoặc đã được xử lý."],
  ["request #4 was already decided", "Yêu cầu #4 đã được xử lý."],
  ["unknown host \"web9\"", "Không tìm thấy host web9."],
  ["open /home/u/.config/ostiary/vault.bin: no such file or directory", "Chưa có vault. Tạo vault ở màn Bắt đầu."],
  ["vault: wrong master key or passphrase", "Sai passphrase."],
  ["Unauthorized", "Phiên đăng nhập đã hết hạn."],
  ["something else entirely", "something else entirely"],
];
for (const [a, b] of errs) assert.strictEqual(friendlyError(a), b, a);
const reasons = [
  ["recursive delete of a directory", "recursive delete of a directory"], // unknown static text falls back
  ["rm: destructive (rule \"rm\")", "rm: phá hủy (theo luật \"rm\")"],
  ["systemctl: mutate (no rule)", "systemctl: thay đổi (không có luật, dùng mức mặc định)"],
  ["reference to sensitive path: ~/.ssh/id_rsa", "Truy cập đường dẫn nhạy cảm: ~/.ssh/id_rsa"],
  ["downloaded code executed by sh", "Code tải về được chạy bởi sh"],
  ["interactive command vim is not supported (no PTY); use sed", "Lệnh tương tác vim không được hỗ trợ (không có PTY); dùng sed"],
];
for (const [a, b] of reasons) assert.strictEqual(reasonVi(a), b, a);
console.log("errors ok");
