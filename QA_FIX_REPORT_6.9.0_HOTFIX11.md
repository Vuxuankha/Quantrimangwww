# QA Fix Report 6.9.0 Hotfix11

## Root cause
Hotfix10 referenced six new UI assets from `index.html`, but `webapi/routes37.py` uses an explicit static-file allowlist and did not include those files. Requests therefore returned HTTP 404, so the browser executed only the legacy navigation.

## Fix
Added the following assets to the explicit allowlist:
- security_modes61.js / security_modes61.css
- security_catalog62.js
- kali63.js
- hotfix9_kali_red.js
- hotfix10_nav_core.js

Also changed the OneClick banner to HOTFIX11 for field verification.
