# Deploy NetworkAutomation lên Render - Hotfix16O Web Production Standards

## Cách deploy
- Kết nối repository Git với Render.
- `render.yaml` đã cấu hình `autoDeploy: true`.
- Mỗi lần push, Render tự build, chạy kiểm tra production và tự start Web.
- Không cần chạy BAT, Agent, PowerShell hay chương trình Windows trên máy người dùng.

## Pipeline tự động
Build Command trong `render.yaml`:

`pip install --upgrade pip && pip install -r requirements-render.txt && python VERIFY_RELEASE.py && python QA_PRODUCTION_GATE.py`

Start Command:

`python render_start.py`

Health Check:

`/api/health`

## Cấu hình runtime
`render.yaml` đặt sẵn:
- `NA_WEB_ONLY_BROWSER=1`
- `NA_ENABLE_AUTOIP=0`
- `NA_PUBLIC_REGISTRATION=1`
- `NA_REGISTRATION_AUTO_ENABLE=1`
- `NA_COOKIE_SECURE=1`

`NA_BOOTSTRAP_ADMIN_PASSWORD` vẫn phải là secret của dịch vụ Render. Không hard-code mật khẩu Admin vào Git.

## Web Native Network
Khi người dùng mở Web, backend nhận IP Internet công khai từ request/proxy và browser có thể đo chất lượng kết nối tới host. Nếu đổi Wi-Fi, 4G/5G hoặc ISP, lần probe tiếp theo cập nhật public IP mới.

Hosted web không thể nhìn xuyên NAT để lấy private IP `192.168.x.x`, MAC/ARP, gateway hay quét LAN của thiết bị người dùng nếu không có local agent. Hotfix16O không giả lập các dữ liệu này.

## Production hardening
- HTTPS response có HSTS khi request tới app được proxy là HTTPS.
- CSP, X-Frame-Options, nosniff, Referrer-Policy và Permissions-Policy được bật.
- HTML/API dùng `Cache-Control: no-store`.
- Static asset có version dùng cache immutable 1 năm.
- Login chỉ tải `style.css` + `app.js`; module nặng tải sau khi xác thực.
