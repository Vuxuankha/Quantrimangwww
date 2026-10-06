# QA Fix Report 6.9.0 Hotfix16O - Web Production Standards

## Mục tiêu
Bản này tối ưu đường chạy hosted Web/Render theo yêu cầu: push code lên host rồi dịch vụ tự build/tự chạy, không cần Agent, BAT, PowerShell hay thao tác Windows trên thiết bị người dùng.

## Thay đổi chính
1. **Performance / Lighthouse readiness**
   - `index.html` chỉ tải `style.css` + `app.js` ở màn hình đăng nhập.
   - Workbench, xterm, terminal, operations, cybersecurity, enterprise, security catalog và Kali UI chỉ tải sau khi `/api/auth/me` xác nhận phiên đăng nhập.
   - Payload khởi tạo giảm từ khoảng **784,556 B xuống 144,852 B raw**; gzip ước tính giảm từ **229,794 B xuống 41,867 B** (giảm khoảng 81.8%).
   - Static asset có query `?v=` dùng `Cache-Control: public, max-age=31536000, immutable`; HTML/API vẫn `no-store`.

2. **SSL/HTTPS hardening**
   - Thêm `Strict-Transport-Security: max-age=31536000; includeSubDomains` khi request thực tế là HTTPS.
   - Thêm `Permissions-Policy: camera=(), microphone=(), geolocation=()`.
   - Giữ CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.

3. **Version clarity**
   - Giữ Core/API `5.9.2-cybersecurity` để không phá launcher/compatibility cũ.
   - `/api/health` bổ sung `core_version`, `ui_version: 6.9.0`, và `release: Hotfix16O Web Production Standards`.

4. **Push-only deployment gate**
   - `render.yaml` tiếp tục `autoDeploy: true`, start bằng `python render_start.py`.
   - Build tự chạy `VERIFY_RELEASE.py` và `QA_PRODUCTION_GATE.py`; nếu release integrity/production invariant lỗi thì build bị chặn trước khi phục vụ người dùng.

## Bộ test chính
| ID | Kiểm tra | Kỳ vọng |
|---|---|---|
| DEP-01 | Render build từ Git | Tự chạy, không cần Windows |
| DEP-02 | Integrity manifest | PASS trước start |
| DEP-03 | Production gate | PASS trước start |
| DEP-04 | `render_start.py` | bind `0.0.0.0:$PORT` |
| DEP-05 | Health endpoint | HTTP 200 |
| SEC-01 | CSP | Có |
| SEC-02 | X-Frame-Options | DENY |
| SEC-03 | nosniff | Có |
| SEC-04 | HSTS trên HTTPS | 1 năm + includeSubDomains |
| SEC-05 | Permissions-Policy | camera/microphone/geolocation disabled |
| PERF-01 | Login initial refs | chỉ style.css + app.js |
| PERF-02 | Initial raw budget | <= 180 KB |
| PERF-03 | Initial gzip budget | <= 60 KB |
| PERF-04 | Heavy modules | lazy-load sau auth |
| PERF-05 | Versioned static cache | immutable 1 năm |
| CACHE-01 | API/HTML | no-store |
| W3C-01 | HTML5 doctype | PASS |
| W3C-02 | `lang="vi"` | PASS |
| W3C-03 | charset UTF-8 | PASS |
| W3C-04 | viewport + description + title | PASS |
| W3C-05 | duplicate ID | 0 |
| W3C-06 | inline event handlers | 0 |
| WEB-01 | UI không yêu cầu BAT/Agent | PASS |
| WEB-02 | public-IP/browser mode | giữ Hotfix16N behavior |
| WEB-03 | LAN private/MAC/gateway | không giả lập; giới hạn browser vẫn áp dụng |

## QA đã chạy trong gói
- Pytest regression: **104/104 PASS**.
- `regression_test.py`: **PASS**.
- `tools/run_release_checks.py`: **PASS**.
- Server smoke: `/api/health` trả 200.
- Static cache smoke: versioned static asset trả `public, max-age=31536000, immutable`.
- HTTPS-proxy smoke: HSTS có mặt khi `X-Forwarded-Proto: https`.
- JS syntax: toàn bộ `webapi/static/*.js` qua `node --check` PASS trong môi trường QA.

## Điểm cần xác nhận trên URL production
Điểm Lighthouse cuối cùng và kết quả Nu/W3C Validator phụ thuộc response/network/runtime của URL đã deploy. Code đã được tối ưu và đặt production gate, nhưng QA không tuyên bố một điểm Lighthouse cụ thể trước khi đo URL production thực tế.

## Giới hạn kiến trúc Web-only
Hosted web có thể nhận public Internet IP của request và đo chất lượng đường truyền browser ↔ host. Web thuần không thể đáng tin cậy lấy private LAN IP `192.168.x.x`, MAC, ARP, gateway hoặc quét LAN của thiết bị người dùng khi không có local agent.
