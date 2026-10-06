# QA Fix Report - Hotfix16M Web-only Browser Mode

## Mục tiêu
Cho phép Web Render vẫn hữu ích khi máy Windows/Local Agent tắt: người dùng chỉ cần mở Web trên PC hoặc điện thoại.

## Thay đổi
- Thêm `/api/v59/browser/probe`, `/browser/ping`, `/browser/download`, `/browser/upload`, `/browser/report`.
- Browser đo latency/jitter/loss bằng HTTPS round-trip từ chính thiết bị đang mở trang.
- Speed test browser đo download/upload giữa browser và Render sau xác nhận của người dùng.
- Dashboard tự fallback sang Browser Mode, hiển thị IP công khai thay vì IP container Render.
- LAN discovery hiển thị rõ `LAN: cần Agent` khi không có collector nội bộ.
- Kết quả Browser được tách theo tài khoản đăng nhập.
- Các POST browser diagnostics được bảo vệ RBAC/CSRF hiện có.

## Giới hạn đúng thiết kế
Web thuần không thể đọc IP LAN private/gateway/ARP/MAC/SNMP hoặc quét LAN khi không có collector trong LAN. Không giả lập dữ liệu này.

## QA
- Python compile: PASS
- JavaScript syntax check: PASS
- Pytest: 109/109 PASS
- Render-style startup: PASS
- `/api/health`: HTTP 200
- Authenticated browser probe/report/summary/download smoke test: PASS
