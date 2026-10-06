# QA FIX REPORT - 6.9.0 Hotfix16R Router Auto Sync

## Loi nguoi dung bao cao
Dashboard van chi hien IP Internet cong khai va 0 thiet bi, du Router API Provider da duoc them. Hotfix16Q chi tao observation; Inventory van can import thu cong va Dashboard khong noi ro Router API chua cau hinh/khong dong bo.

## Sua trong Hotfix16R
- Dashboard goi Router API sync truoc khi tinh lai Inventory.
- Admin: Cloud/WAN provider tu dong import IPv4 private hop le vao Inventory.
- Browser Direct: browser doc client; observation cua Admin tu dong import neu `auto_import` khong tat.
- Master Automation `LIVE_DISCOVERY` khong con goi host/LAN discovery; thay bang Router API sync an toan.
- Them chip `Router API` o header va canh bao ro `chua cau hinh` / `loi` / `N thiet bi`.
- Doi nhan `IP mang` thanh `IP Internet` de khong nham voi LAN IP.
- Van khoa private destination o server-side provider; Render khong quet LAN.

## Gioi han that
Khong co API/cloud/controller cua router thi web HTTPS tren Render khong the tu biet gateway/model/password va khong the tu quet LAN cua may nguoi dung. Router API van can duoc cau hinh mot lan trong chinh giao dien Web.
