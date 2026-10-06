# NetworkAutomation Cybersecurity UI 6.9.0 - Hotfix16Q Router API Provider

Ban hosted Web/Render chay doc lap tren may chu. Nguoi dung chi can trinh duyet tren may tinh hoac dien thoai; khong can BAT, Agent, PowerShell hay dich vu Windows cuc bo.

## Diem moi Hotfix16Q
### Router API Provider - khong can Agent
- Giu `NA_WEB_ONLY_BROWSER=1`: Render tuyet doi khong quet LAN cua host.
- Trang **Kham pha mang** doc danh sach client tu Router/Controller API.
- Ho tro 2 cach thuc thi:
  - **Cloud/WAN API**: Render goi public HTTPS/cloud endpoint.
  - **Browser Direct**: trinh duyet goi truc tiep HTTPS router trong LAN khi router cho phep CORS/Private Network Access.
- Provider co san: MikroTik RouterOS REST, UniFi Cloud Connector, Generic HTTPS JSON server, Generic Browser Direct JSON.
- Private/loopback/link-local destination bi chan o server-side provider de tranh SSRF. Redirect server-side cung bi chan.
- Browser Direct password/token chi luu trong `sessionStorage` cua tab/browser session va khong duoc luu tren Render.
- Client Router API chi duoc ghi nhan/import neu co IPv4 private LAN hop le.

### Production Web
- Login chi tai 2 asset chinh; module nang lazy-load sau dang nhap.
- Static asset co cache versioned/immutable; HTML va API giu `no-store`.
- HSTS cho HTTPS, CSP, Permissions-Policy, X-Frame-Options DENY va nosniff.
- Render build tu chay `VERIFY_RELEASE.py` + `QA_PRODUCTION_GATE.py` truoc khi start.

## Cach chon Router API
1. **UniFi**: uu tien `unifi_cloud`; tao API Key trong UniFi Site Manager va dung Cloud Connector. Khong can mo router LAN ra Internet.
2. **MikroTik**: RouterOS REST nam duoi `/rest` va dung Basic Auth. Ban hosted chi cho server-side khi endpoint la public HTTPS an toan; neu router chi co private IP thi can mot gateway/reverse proxy HTTPS duoc bao ve, khong public management truc tiep.
3. **Router/controller co HTTPS GET JSON API trong LAN**: dung `generic_browser` neu router co HTTPS tin cay + CORS/PNA. OpenWrt ubus JSON-RPC POST chua co preset rieng trong ban nay.
4. **Router/controller khac co cloud API**: dung `generic_server` va map `list_path`, `ip_field`, `mac_field`, `hostname_field`, `status_field`, `interface_field` trong Options JSON.

## Render
- Build/QA: lay tu `render.yaml`.
- Start: `python render_start.py`.
- Health: `/api/health`.
- Auto deploy: bat.

`NA_BOOTSTRAP_ADMIN_PASSWORD` phai duoc luu duoi dang Render secret; khong dua mat khau that vao source code.
