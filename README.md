# NetworkAutomation Cybersecurity UI 6.9.0 - Hotfix16O Web Production Standards

Bản hosted Web/Render chạy độc lập trên máy chủ. Người dùng chỉ cần trình duyệt trên máy tính hoặc điện thoại; không cần BAT, Agent, PowerShell hay dịch vụ Windows cục bộ.

## Điểm mới Hotfix16O
- Tối ưu tải ban đầu cho Lighthouse: login chỉ tải 2 asset chính; module nặng lazy-load sau đăng nhập.
- Static asset có cache versioned/immutable; HTML và API giữ `no-store`.
- Bổ sung HSTS cho HTTPS và `Permissions-Policy`.
- `/api/health` hiển thị rõ Core/API `5.9.2-cybersecurity`, UI `6.9.0` và tên release.
- Render build tự chạy `VERIFY_RELEASE.py` + `QA_PRODUCTION_GATE.py` trước khi start.
- Production gate hiện kiểm tra 37 điều kiện về HTML, performance budget, HTTPS/security, cache, asset và deploy config.

## Mạng đang dùng
- Web tự lấy **IP Internet công khai** từ request HTTPS/proxy.
- Trang **Tốc độ & Đường truyền** đo kết nối browser ↔ host.
- Không giả lập private LAN IP, MAC, ARP hoặc gateway.

## Render
- Build/QA: tự lấy từ `render.yaml`.
- Start: `python render_start.py`.
- Health: `/api/health`.
- Auto deploy: bật.

Lưu ý: `NA_BOOTSTRAP_ADMIN_PASSWORD` phải được lưu dưới dạng Render secret; không đưa mật khẩu thật vào source code.
