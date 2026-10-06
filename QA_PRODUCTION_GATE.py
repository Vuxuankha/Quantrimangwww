"""Hotfix16O production gate for Render/Web deployment.

Pure-Python, no browser or Windows dependency. It validates the release's
critical deployment, HTML, performance-budget and HTTPS/security invariants.
"""
from __future__ import annotations

import gzip
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / 'webapi' / 'static'


class IndexAudit(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids=[]; self.html_lang=''; self.title_depth=0; self.title=''
        self.meta=[]; self.buttons=[]; self.inline_handlers=[]
    def handle_starttag(self, tag, attrs):
        d=dict(attrs)
        if 'id' in d: self.ids.append(d['id'])
        if tag=='html': self.html_lang=d.get('lang','')
        if tag=='meta': self.meta.append(d)
        if tag=='title': self.title_depth+=1
        if tag=='button': self.buttons.append(d)
        for k,_ in attrs:
            if k.lower().startswith('on'): self.inline_handlers.append(k)
    def handle_endtag(self, tag):
        if tag=='title' and self.title_depth: self.title_depth-=1
    def handle_data(self, data):
        if self.title_depth: self.title += data


def main() -> int:
    checks=[]
    def check(name, condition, detail=''):
        checks.append((name, bool(condition), detail))

    index_path=STATIC/'index.html'
    app_path=STATIC/'app.js'
    sec_path=ROOT/'webapi'/'security37.py'
    main_path=ROOT/'webapi'/'main.py'
    runtime_path=ROOT/'webapi'/'runtime37.py'
    routes_path=ROOT/'webapi'/'routes37.py'
    render_path=ROOT/'render.yaml'
    req_path=ROOT/'requirements.txt'

    index=index_path.read_text(encoding='utf-8')
    app=app_path.read_text(encoding='utf-8')
    sec=sec_path.read_text(encoding='utf-8')
    main_src=main_path.read_text(encoding='utf-8')
    runtime=runtime_path.read_text(encoding='utf-8')
    routes=routes_path.read_text(encoding='utf-8')
    render=render_path.read_text(encoding='utf-8')
    req=req_path.read_text(encoding='utf-8')

    audit=IndexAudit(); audit.feed(index)
    metas={(m.get('name') or '').lower():m.get('content','') for m in audit.meta if m.get('name')}
    charsets=[m.get('charset','').lower() for m in audit.meta if m.get('charset')]
    duplicate_ids=sorted({x for x in audit.ids if audit.ids.count(x)>1})
    refs=re.findall(r'(?:src|href)="/static/([^"?]+)', index)

    check('HTML doctype', index.lstrip().lower().startswith('<!doctype html>'))
    check('HTML lang', audit.html_lang=='vi', audit.html_lang)
    check('UTF-8 charset', 'utf-8' in charsets, repr(charsets))
    check('Viewport meta', bool(metas.get('viewport')))
    check('Description meta', bool(metas.get('description')))
    check('Document title', bool(audit.title.strip()), audit.title.strip())
    check('No duplicate IDs', not duplicate_ids, ','.join(duplicate_ids))
    check('No inline event handlers', not audit.inline_handlers, ','.join(audit.inline_handlers))
    check('No mixed-content HTTP asset', 'src="http://' not in index.lower() and 'href="http://' not in index.lower())

    check('Minimal initial static refs', refs==['style.css','app.js'], repr(refs))
    initial_files=[index_path]+[STATIC/r for r in refs]
    raw=sum(f.stat().st_size for f in initial_files)
    gz=sum(len(gzip.compress(f.read_bytes(),compresslevel=9)) for f in initial_files)
    check('Initial raw budget <= 180 KB', raw<=180_000, str(raw))
    check('Initial gzip budget <= 60 KB', gz<=60_000, str(gz))
    check('Versioned initial assets', 'style.css?v=6920' in index and 'app.js?v=6920' in index)
    check('Lazy loader after auth', 'await naLoadOperationalAssets()' in app and "state.user=await api('/auth/me')" in app)

    feature_scripts=['workbench45.js','vendor/xterm.js','live46.js','terminal46.js','operations47.js','operations50.js','cybersecurity51.js','enterprise592.js','enterprise600.js','security_modes61.js','security_catalog62.js','kali63.js','hotfix9_kali_red.js','hotfix10_nav_core.js']
    feature_styles=['workbench45.css','vendor/xterm.css','terminal46.css','operations47.css','operations50.css','cybersecurity51.css','enterprise592.css','enterprise600.css','security_modes61.css']
    missing_files=[n for n in feature_scripts+feature_styles if not (STATIC/n).is_file()]
    missing_manifest=[n for n in feature_scripts+feature_styles if repr(n) not in app]
    blocked=[n for n in feature_scripts+feature_styles if ("'"+n+"'") not in routes]
    check('Lazy asset files exist', not missing_files, ','.join(missing_files))
    check('Lazy asset manifest complete', not missing_manifest, ','.join(missing_manifest))
    check('Static allowlist complete', not blocked, ','.join(blocked))

    check('CSP present', 'Content-Security-Policy' in sec and "default-src 'self'" in sec)
    check('HSTS HTTPS-only', 'Strict-Transport-Security' in sec and "if str(request.url.scheme).lower()=='https'" in sec)
    check('HSTS one year', 'max-age=31536000; includeSubDomains' in sec)
    check('Permissions Policy', 'Permissions-Policy' in sec and 'camera=(), microphone=(), geolocation=()' in sec)
    check('X-Frame DENY', "'X-Frame-Options':'DENY'" in sec)
    check('nosniff', "'X-Content-Type-Options':'nosniff'" in sec)
    check('Sensitive responses no-store', "security_headers['Cache-Control']='no-store'" in sec)
    check('Versioned static immutable cache', 'public, max-age=31536000, immutable' in sec)

    check('Health UI version', "UI_VERSION='6.9.0'" in runtime and "'ui_version':UI_VERSION" in main_src)
    check('Health core version explicit', "'core_version':VERSION" in main_src)
    check('Health release explicit', "RELEASE='Hotfix16O Web Production Standards'" in runtime and "'release':RELEASE" in main_src)

    check('Render Python start', 'startCommand: python render_start.py' in render)
    check('Render auto deploy', 'autoDeploy: true' in render)
    check('Browser-only mode', 'NA_WEB_ONLY_BROWSER' in render and 'value: "1"' in render)
    check('No Windows action in hosted UI', '.bat' not in index.lower() and '.bat' not in app.lower())
    check('Render runtime dependencies', all(x in req for x in ('fastapi','uvicorn','pydantic','argon2-cffi')))

    for path in [ROOT/'render_start.py', sec_path, main_path, runtime_path]:
        try:
            compile(path.read_text(encoding='utf-8'), str(path), 'exec')
            ok=True; detail=''
        except SyntaxError as exc:
            ok=False; detail=str(exc)
        check('Python syntax '+path.name, ok, detail)

    failed=[c for c in checks if not c[1]]
    for name,ok,detail in checks:
        suffix=f' ({detail})' if detail else ''
        print(('PASS' if ok else 'FAIL')+': '+name+suffix)
    print(f'\nProduction gate: {len(checks)-len(failed)}/{len(checks)} PASS; initial payload raw={raw} bytes, gzip={gz} bytes')
    if failed:
        print('BLOCK DEPLOY: '+', '.join(x[0] for x in failed), file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
