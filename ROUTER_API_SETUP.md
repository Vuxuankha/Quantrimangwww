# Router API Setup - Hotfix16Q

## Muc tieu
Web chay tren Render va doc danh sach client LAN tu router/controller, khong cai Agent tren Windows va khong quet LAN cua host Render.

## 1. UniFi Cloud Connector - khuyen nghi neu dung UniFi
Chon provider: `unifi_cloud`.

Can mot API Key trong UniFi Site Manager. Web luu token o backend duoi dang ma hoa va Render goi `api.ui.com` Cloud Connector.

Options JSON can co:
- `console_id`: ID console UniFi.
- `endpoint`: Network integration endpoint tra danh sach connected clients.
- `list_path`: thuong la `data` neu response boc danh sach trong truong data.
- `ip_field`, `mac_field`, `hostname_field`, `status_field`, `interface_field`: map theo response API thuc te.

Uu diem: sau khi cau hinh mot lan, Render co the doc API ma khong can may nguoi dung nam trong LAN.

## 2. MikroTik RouterOS REST
Chon provider: `mikrotik_rest`.

RouterOS REST dung HTTPS `/rest` va Basic Auth. Web doc DHCP lease + ARP tu REST API.

Trong hosted mode, backend chi cho phep public HTTPS endpoint. Private IP nhu `https://192.168.1.1` se bi chan tu Render de tranh quet nham host/private network.

Khong nen expose management cua router truc tiep ra Internet. Neu can server-side, nen dung mot HTTPS gateway/reverse proxy/VPN/zero-trust endpoint duoc bao ve.

## 3. Generic Browser Direct - router API chi co trong LAN
Chon provider: `generic_browser`.

Dieu kien:
- Router/API phai la HTTPS.
- Certificate phai duoc browser tin cay.
- Router phai cho phep CORS tu origin cua web NetworkAutomation.
- Neu browser ap dung Private Network Access, router/reverse proxy phai cho phep PNA preflight.

Password/token khong luu tren Render. No chi duoc giu trong `sessionStorage` cua browser session.

Sau khi luu Base URL, trang se tu reload mot lan de CSP cho phep dung origin HTTPS cua router.

Options JSON mau:
```json
{
  "endpoint": "/api/clients",
  "list_path": "",
  "ip_field": "ip",
  "mac_field": "mac",
  "hostname_field": "hostname",
  "status_field": "status",
  "interface_field": "interface",
  "online_values": "online,active,bound,connected,true,1",
  "auth_mode": "none",
  "token_header": "X-API-Key"
}
```

`auth_mode` ho tro: `none`, `basic`, `bearer`, `x-api-key`.

## 4. Generic Cloud/WAN JSON API
Chon provider: `generic_server`.

Dung khi router/controller co public HTTPS/cloud API tra JSON. Backend Render goi endpoint va normalize danh sach client theo Options JSON.

Hosted mode se chan:
- localhost / loopback
- private IP
- link-local
- redirect sang URL khac

Muc dich la ngan SSRF va ngan Render bi bien thanh LAN scanner.

## Tu dong refresh
Khi mo trang `Kham pha mang`, neu Router API da bat, web se tu doc lai client (throttle 30 giay). Nguoi dung van co nut `Doc thiet bi tu Router API` de refresh thu cong.

## Import Inventory
Router API chi tao observation. Chi Admin moi co the bam `Nhap vao Inventory`. Chi IPv4 private LAN hop le duoc import.

## Luu y quan trong
Neu router chi co `http://192.168.x.x`, website HTTPS tren Render khong duoc phep goi truc tiep vi mixed content. Can HTTPS API hoac cloud/public HTTPS integration.
