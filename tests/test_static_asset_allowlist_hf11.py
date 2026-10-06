import re
from pathlib import Path


def test_every_index_static_asset_is_explicitly_allowed():
    root = Path(__file__).resolve().parents[1]
    index = (root / 'webapi/static/index.html').read_text(encoding='utf-8')
    routes = (root / 'webapi/routes37.py').read_text(encoding='utf-8')
    refs = re.findall(r'(?:src|href)="/static/([^"?]+)', index)
    missing = [name for name in refs if ("'" + name + "'") not in routes]
    assert not missing, f'static assets referenced by index but blocked by whitelist: {missing}'
