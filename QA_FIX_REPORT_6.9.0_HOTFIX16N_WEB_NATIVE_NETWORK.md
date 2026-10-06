# QA Fix Report - Hotfix16N Web Native Network

## Mục tiêu
Bỏ Local Agent khỏi bản Render. Người dùng chỉ mở Web trên PC/điện thoại; Web tự xác định địa chỉ Internet đang dùng và tự đo chất lượng kết nối.

## Thay đổi
- Xóa launcher/config/runtime Local Agent 16L khỏi gói phát hành.
- Render bật `NA_WEB_ONLY_BROWSER=1`; không còn token Agent hoặc chế độ ưu tiên Agent.
- Thanh trạng thái tự gọi `/api/v59/browser/probe` khi đăng nhập và định kỳ, hiển thị IP Internet công khai của thiết bị đang mở Web.
- Trang Tốc độ & Đường truyền luôn đo từ browser qua HTTPS; không chạy phép đo từ container Render.
- Endpoint Monitoring chuyển thành Web Host Monitoring; không còn tạo/thu hồi Agent Token.
- Hosted LAN discovery bị vô hiệu hóa để tránh nhầm mạng private của container Render với LAN của người dùng.

## Giới hạn kỹ thuật
Web thuần có thể tự nhận IP Internet công khai và đo RTT/jitter/loss/download/upload qua HTTPS. Trình duyệt hiện đại không cung cấp API chung, đáng tin cậy để website đọc IP private 192.168.x.x, gateway, ARP/MAC hoặc quét LAN.
