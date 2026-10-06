# QA Fix Report 6.9.0 Hotfix16k - Render No MFA

## Muc tieu
Bo buoc thiet lap/xac thuc MFA tren ban Render theo yeu cau nguoi dung. Dang nhap Render chi dung tai khoan + mat khau.

## Thay doi
- `render_start.py` dat `NA_MFA_REQUIRED=0` va `NA_DISABLE_MFA=1` cho Render.
- Khi Render khoi dong, cap nhat `web_security_policy51.mfa_required=0`.
- Xoa trang thai/secret MFA cu cua tai khoan trong runtime DB va xoa MFA challenge cu.
- Khong thay doi launcher Windows/local; MFA local giu nguyen theo cau hinh san pham.

## Ky vong
- Dang nhap dung username/password se vao he thong ngay.
- Khong hien hop thoai `Thiet lap MFA`.
- Tai khoan dang ky moi khong bi ep enroll Authenticator.
