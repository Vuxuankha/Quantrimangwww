# Deploy NetworkAutomation len Render - Hotfix16Q Router API Provider

## Cach deploy
- Ket noi repository Git voi Render.
- `render.yaml` da cau hinh `autoDeploy: true`.
- Moi lan push, Render tu build, chay release integrity + production gate va tu start Web.
- Khong can BAT, Agent, PowerShell hay chuong trinh Windows tren may nguoi dung.

## Pipeline tu dong
Build Command:

`pip install --upgrade pip && pip install -r requirements-render.txt && python VERIFY_RELEASE.py && python QA_PRODUCTION_GATE.py`

Start Command: `python render_start.py`

Health Check: `/api/health`

## Router API Provider
- Server-side provider chi goi HTTPS endpoint cong khai/cloud. Private, loopback va link-local bi chan.
- Browser Direct provider chi goi dung HTTPS origin da cau hinh; CSP duoc cap nhat theo origin do sau khi reload.
- Browser Direct credential chi giu trong `sessionStorage`, khong luu tren Render.
- LAN scan cu `/api/scan`, queued `SCAN` va auto-discovery tren Render van bi khoa.

### UniFi Cloud
- Tao API key trong UniFi Site Manager.
- Chon `unifi_cloud`.
- Dien `console_id`, endpoint Network integration va field mapping trong Options JSON.
- Render goi `api.ui.com`; Cloud Connector proxy ve console.

### Browser Direct
Router phai dap ung tat ca:
- HTTPS certificate duoc browser tin cay.
- API tra JSON.
- CORS cho origin cua Web NetworkAutomation.
- Neu browser ap dung Private Network Access, router/reverse proxy phai cho phep PNA preflight.

Neu router chi co `http://192.168.x.x` thi trang HTTPS tren Render khong duoc phep goi truc tiep do mixed-content.

## Runtime secrets
`NA_BOOTSTRAP_ADMIN_PASSWORD` van phai la Render secret. Khong hard-code password/API token vao Git.
