## UI 6.6.0 - QA round 3 P1/P2 fixes
- Accept Analyst in account create/edit schema.
- Allow Analyst to change own password.
- Atomic device + current Presence delete with rollback on failure.
- Remove false-positive delete success caused by bool(non-empty dict).
- Add runtime regression tests for role and device lifecycle.

## UI 6.5.0 - Canonical Presence Engine / QA P1 fixes
- Delete device now cleans current Presence state and records a Deleted audit event.
- Removed the 128-device truncation; all managed targets are processed in bounded batches.
- Presence combines managed inventory, current LAN discovery, and recently discovered hosts.
- Dashboard Online/Offline/Unknown/Total now use one Presence source of truth.
- Added tests/test_presence65.py and regression_test.py to the shipped release.
- Release checks run core regression even when optional Paramiko/PySNMP are unavailable.

# Changelog 5.9.0

- Thêm mục Mạng & Chẩn đoán > Tốc độ & Đường truyền.
- Kiểm tra nhẹ latency, jitter, packet loss tới gateway và public probe.
- Kiểm tra HTTPS/WAN reachability độc lập với dữ liệu cũ.
- Speed Test WAN thủ công: mặc định download 5 MB + upload 2 MB, yêu cầu xác nhận trước khi dùng băng thông.
- Lưu lịch sử line quality / bandwidth vào SQLite để theo dõi xu hướng.
- Không tự chạy bandwidth test nền; không thay đổi cấu hình mạng.
- API/UI build: 5.9.0-cybersecurity.

## UI 6.4.0 - Functional Reliability

- Lưu trạng thái Online/Offline/Unknown của máy theo thời gian.
- Ghi lịch sử thay đổi trạng thái và thời điểm thấy máy lần cuối.
- Thêm cơ chế xác minh 2 bước khi vừa mất phản hồi để giảm báo Offline giả.
- Thêm Identity Guard phát hiện một MAC xuất hiện trên nhiều IP.
- Dashboard hiển thị số xung đột định danh và lịch sử máy rời/kết nối lại mạng.
- Mở rộng Quản trị > Kiểm tra chức năng cho Presence/Identity Guard.


## UI 6.7.1
- Fixed preliminary Live Discovery `sources` normalization and `source_counts`.
- SELF_CHECK now resolves custom/external data roots consistently and SELF_CHECK.bat forwards CLI options.
- Added 6.7.1 regression tests and corrected the regression report label.


### UI 6.8.0
- Added persistent Master Automation coordinator in Operations Center.
- Added safe periodic monitoring/maintenance task registry and execution history.
- Fixed Vulnerability Center inventory endpoint path.

## UI 6.9.0 - Daily Safe Auto-Completion
- Added persistent auto-completion switch to "Việc cần làm hôm nay".
- Safe 5-minute cycle runs Presence, LAN Discovery, Alert Rules, Incident/RCA, Line Quality and DB Backup.
- Added AUTO DONE / CHECKED / NEEDS HUMAN evidence per checklist category.
- Automation never closes security findings/cases or performs vulnerability/MFA/credential/config/delete/restore actions.
- Added Admin-only enable/disable/run-now APIs and regression tests.

## UI 6.9.0 - QA Hotfix16g Render Startup Headless Tk Fix
- Fixed FastAPI lifespan failure on Render when `_tkinter` is unavailable.
- `extra_pages`, `nms_v3`, and `nms_v4` now allow schema helpers to load in headless Linux while preserving Tk UI on desktop Windows.
- Verified Render-style startup and `/api/health` without `_tkinter`.

## Hotfix16h - Render Admin Bootstrap
- Fresh Render AutoDB now creates the first Admin from secure environment variables.
- Prevents `INVALID_CREDENTIALS` caused by an empty cloud `app_users` table.
- No password is hard-coded or printed. Existing accounts are never overwritten.

## Hotfix16L3 - Local Agent AutoStart + Render
- Thêm ONECLICK/AutoStart chạy Local Agent ẩn cùng Windows.
- Thêm watchdog tự khởi động lại Agent và file STATUS để chẩn đoán.
- Dashboard cảnh báo rõ khi Render chưa cấu hình `NA_LOCAL_AGENT_SHARED_TOKEN`.
- Chip Agent có thể bấm để xem trạng thái cài đặt và IP gần nhất.


## QA Hotfix16L4 - Fast Local Agent heartbeat
- Local Agent check-in no longer waits for LAN scan.
- LAN scan runs in background after first heartbeat.
- Test mode verifies token/IP with `--no-scan`.
- Removed blocking reverse DNS from fast LAN discovery.

## Hotfix16L5 - Local Agent auth recovery
- Detect HTTP 401 agent-token mismatch without Python traceback.
- Safe token/config writer for Windows CMD special characters.
- Interactive re-entry and immediate retest of `NA_LOCAL_AGENT_SHARED_TOKEN`.

## Hotfix16L6
- Netspeed uses Windows Local Agent IP/gateway and line-quality probes instead of Render container networking.

## Hotfix16M - Web-only Browser Mode fallback
- Khi Local Agent OFFLINE hoặc máy Windows tắt, Web tự chuyển sang Browser Mode.
- Điện thoại/PC chỉ cần mở Web để đo HTTPS latency, jitter, packet loss và tốc độ truyền tới Render.
- Thanh trạng thái hiển thị `Web: ONLINE`, IP công khai của thiết bị và `LAN: cần Agent` thay vì dùng nhầm IP container Render.
- Local Agent trở thành tùy chọn cho dữ liệu LAN riêng: IP 192.168.x.x, gateway, ARP/MAC, SNMP và quét thiết bị nội bộ.
- Browser Mode không giả lập các quyền mạng thô mà trình duyệt không có.

- Hotfix16N: removed Local Agent requirement from Render; browser-native public IP and HTTPS network diagnostics are automatic.
