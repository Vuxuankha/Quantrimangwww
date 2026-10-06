# Daily Server Audit Automation

Bộ script PowerShell tự động hóa các mục an toàn trong checklist `daily.xlsx`.

## Tự động hóa được
- Windows System/Application/Security Event Log: ID 41, 6008, 10016, 4624, 4625, 4672.
- Phát hiện nhiều lần đăng nhập thất bại.
- CPU, RAM, dung lượng ổ đĩa.
- Dịch vụ Automatic nhưng không chạy.
- Windows Firewall profile.
- TCP listening ports để rà soát dịch vụ mở.
- Microsoft Defender status + detection gần đây.
- Thành viên Local Administrators và trạng thái RDP.
- Hotfix mới nhất.
- Kiểm tra độ mới của file backup tại các thư mục được cấu hình.
- Xuất HTML + JSON.

## Không chạy tự động trong job hằng ngày
- ARP spoof / DHCP spoof / rogue AP.
- Masscan/Nmap quét rộng dải mạng nếu chưa có phạm vi được phê duyệt.
- Tự động sửa lỗi bằng `sfc`, `DISM`, `chkdsk`, `bootrec` vì các lệnh này có thể thay đổi hệ thống hoặc cần reboot.

Các mục trên nên là quy trình xử lý sự cố/kiểm thử bảo mật riêng và chỉ chạy trên hệ thống được phép.

## Cài đặt
1. Copy thư mục vào máy Windows Server, ví dụ `C:\DailyAudit`.
2. Sửa `config.json`.
3. Mở PowerShell **Run as Administrator**.
4. Test thủ công:
   `powershell -ExecutionPolicy Bypass -File .\Daily-Audit.ps1`
5. Cài lịch chạy hằng ngày lúc 07:30:
   `powershell -ExecutionPolicy Bypass -File .\Install-ScheduledTask.ps1 -RunAt 07:30`

## Cấu hình cần sửa
- `HoursBack`: khoảng thời gian log cần kiểm tra.
- `FailedLoginWarnCount`: số lần login fail để báo cảnh báo.
- `ExpectedListeningPorts`: các TCP port được phép/được kỳ vọng trên server.
- `BackupPaths`: thêm các thư mục backup, ví dụ `D:\Backup`.
- Các ngưỡng CPU/RAM/Disk.

## Bước mở rộng nên làm
Có thể thêm xuất CSV/Excel, gửi email/Telegram/Teams, gom báo cáo nhiều server, query SQL/IIS, kiểm tra certificate sắp hết hạn, kiểm tra Windows Update và tạo dashboard tổng hợp.
