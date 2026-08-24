from __future__ import annotations

import os
from urllib.parse import urlencode
from urllib.request import urlopen

reference = os.environ["SECRET_API_KEY"]
base_url = os.environ["API_BASE"].rstrip("/")
url = f"{base_url}/health?{urlencode({'secret': reference})}"

with urlopen(url, timeout=10) as response:
    print(response.read().decode("utf-8"))
