# QA FIX REPORT - 6.9.0 Hotfix16Q Router API Provider

## Muc tieu
Thay the hanh vi LAN scan sai tren hosted Render bang Router/Controller API, khong quay lai Local Agent va khong quet subnet cua host.

## Thay doi chinh
- Them `webapi/routerapi69.py` voi Router API Provider.
- Them `webapi/static/routerapi69.js` va ghi de trang `Kham pha mang` trong Web-only mode.
- Provider:
  - MikroTik RouterOS REST - server HTTPS.
  - UniFi Cloud Connector - server HTTPS qua `api.ui.com`.
  - Generic JSON API - server HTTPS.
  - Generic JSON API - browser direct HTTPS/CORS.
- Browser Direct credential chi o `sessionStorage`; backend xoa server-side secret/token neu provider la Browser Direct.
- CSP `connect-src` chi mo dung HTTPS origin Browser Direct da cau hinh.
- Server provider chan private/loopback/link-local destination trong hosted mode.
- Chan HTTP redirect trong server provider de tranh redirect SSRF.
- Ket qua Router API duoc normalize va loc chi IPv4 private LAN truoc khi ghi observation/import.
- LAN scan cu tren Render van bi hard-block o `/api/scan`, queued `SCAN` va auto discovery.
- Trang scan tu refresh Router API khi mo trang, throttle 30 giay.
- Asset cache-buster: `6922`.
- Release: `Hotfix16Q Router API Provider`.

## QA
- Full pytest: 116/116 PASS.
- Production Gate: 48/48 PASS.
- Initial payload: 146341 bytes raw; 42517 bytes gzip.
- Python syntax: PASS cho render_start, security37, main, runtime37, routerapi69.
- JavaScript syntax: PASS khi Node runtime kha dung.

## Security boundary
- Render khong duoc quet private LAN cua nguoi dung.
- Generic server-side API khong duoc goi private destination trong hosted mode.
- Redirect server-side bi chan.
- Browser Direct chi chay trong browser va phu thuoc HTTPS/CORS/PNA cua router.
- Browser Direct secret/token khong duoc luu tren Render.

## Van hanh
Sau khi push Git, Render van dung pipeline:
`VERIFY_RELEASE.py -> QA_PRODUCTION_GATE.py -> render_start.py`.
Khong can BAT, PowerShell, Windows Service hay Local Agent.

## Gioi han
Khong co mot API chung cho moi router. Admin can cau hinh provider, endpoint va field mapping dung voi hang/model/router firmware dang su dung. Neu router khong co HTTPS API/CORS va khong co cloud API, Web-only khong the doc LAN client ma khong co mot gateway/collector trung gian.
