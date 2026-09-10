"""
Capture store for evilgenie.

Records EVERYTHING observed while the attacker performs the auth flow in the
browser — hosts, requests, query params, POST fields (form / JSON / multipart),
request headers, Set-Cookie cookies, response bodies (text only, bounded),
redirects and JSON body values — and presents it all for interactive selection.
Nothing is pre-filtered out of the menus; token-ish things are only
*preselected* for convenience.

Handlers are invoked from Playwright's dispatcher thread, so all mutations go
through a lock.
"""

import json
import re
import threading
from urllib.parse import urlparse, parse_qsl

# Mimes worth keeping bodies for (sub_filter + body-token analysis)
TEXT_MIMES = ("text/html", "application/json", "application/javascript",
              "text/javascript", "application/xml", "text/xml")
MAX_BODY_BYTES = 2 * 1024 * 1024   # 2 MB cap per response body
MAX_KEYS_PER_BODY = 200            # cap JSON keys scanned per response

# Token-ish names (used ONLY for menu preselection, never for filtering)
TOKENISH_RE = re.compile(r"(token|session|auth|jwt|csrf|xsrf|sid|bearer|ticket)", re.IGNORECASE)


def _parse_set_cookie(header):
    """Parse one Set-Cookie header value -> dict(name, domain, path, has_expiry)."""
    parts = header.split(";")
    if not parts or "=" not in parts[0]:
        return None
    name, _, _ = parts[0].partition("=")
    name = name.strip()
    if not name:
        return None
    rec = {"name": name, "domain": None, "path": None, "has_expiry": False}
    for attr in parts[1:]:
        k, _, v = attr.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "domain":
            rec["domain"] = v
        elif k == "path":
            rec["path"] = v
        elif k in ("expires", "max-age"):
            rec["has_expiry"] = True
    return rec


def _flatten_json(obj, prefix=""):
    """Flatten nested JSON into {dotted.path: value} scalars."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.update(_flatten_json(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            out.update(_flatten_json(v, key))
    else:
        out[prefix] = obj
    return out


def _parse_multipart(data, ctype_full):
    """Best-effort extraction of field name/value pairs from a multipart body."""
    m = re.search(r'boundary=["\']?([^;"\']+)', ctype_full or "")
    if not m:
        return {}
    boundary = m.group(1)
    fields = {}
    for part in data.split("--" + boundary):
        pm = re.search(r'name="([^"]+)"[^\n]*\r?\n\r?\n(.*?)\r?\n?$', part, re.DOTALL)
        if pm:
            fields[pm.group(1)] = pm.group(2)[:120]
    return fields


class CaptureStore:
    def __init__(self):
        self._lock = threading.Lock()
        self.requests = []          # {url, method, host, path, resource_type}
        self.posts = []             # {url, host, path, ctype, fields, raw}
        self.query_fields = []      # {host, path, name, sample}   (GET query params)
        self.req_headers = []       # {host, path, name, sample}   (deduped per host+name)
        self.responses = []         # {url, host, path, status, mime}
        self.bodies = {}            # url -> body text (bounded, text mimes only)
        self.cookies = {}           # domain -> {name: {"has_expiry": bool}}
        self.redirects = []         # {host, path, location}
        self.body_values = []       # {host, path, name, sample, search, tokenish}
        self.final_url = None
        self._seen_qf = set()
        self._seen_hdr = set()

    # ---- Playwright event handlers -------------------------------------

    def on_request(self, request):
        try:
            parsed = urlparse(request.url)
            host = parsed.hostname or ""
            path = parsed.path or "/"
            with self._lock:
                self.requests.append({
                    "url": request.url, "method": request.method,
                    "host": host, "path": path,
                    "resource_type": request.resource_type,
                })
            self._capture_query(parsed, host, path)
            self._capture_headers(request, host, path)
            if request.method.upper() in ("POST", "PUT", "PATCH"):
                self._capture_post(request, host, path)
        except Exception:
            pass  # never let capture break the browser session

    def on_response(self, response):
        try:
            parsed = urlparse(response.url)
            host = parsed.hostname or ""
            path = parsed.path or "/"
            headers = response.headers
            mime = headers.get("content-type", "").split(";")[0].strip().lower()
            with self._lock:
                self.responses.append({
                    "url": response.url, "host": host, "path": path,
                    "status": response.status, "mime": mime,
                })
            self._capture_cookies(response, host)
            if 300 <= response.status < 400:
                loc = headers.get("location")
                if loc:
                    lp = urlparse(loc)
                    with self._lock:
                        self.redirects.append({
                            "host": lp.hostname or host,
                            "path": lp.path or "/",
                            "location": loc,
                        })
            if any(m in mime for m in TEXT_MIMES):
                self._capture_body(response, host, path, mime)
        except Exception:
            pass

    # ---- individual capture helpers ------------------------------------

    def _capture_query(self, parsed, host, path):
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            key = (host, path, name)
            with self._lock:
                if key in self._seen_qf:
                    continue
                self._seen_qf.add(key)
                self.query_fields.append({
                    "host": host, "path": path, "name": name,
                    "sample": str(value)[:60],
                })

    def _capture_headers(self, request, host, path):
        for name, value in request.headers.items():
            if not value:
                continue
            name = name.lower()
            key = (host, name)
            with self._lock:
                if key in self._seen_hdr:
                    continue
                self._seen_hdr.add(key)
                sample = value if len(value) <= 24 else value[:21] + "..."
                self.req_headers.append({
                    "host": host, "path": path, "name": name, "sample": sample,
                })

    def _capture_post(self, request, host, path):
        data = request.post_data
        if data is None:
            return
        ctype_full = request.headers.get("content-type", "")
        ctype = ctype_full.split(";")[0].strip().lower()
        fields = {}
        kind = "post"
        if "json" in ctype:
            kind = "json"
            try:
                fields = {k: str(v) for k, v in _flatten_json(json.loads(data)).items()}
            except (ValueError, TypeError):
                fields = {}
        elif "multipart" in ctype:
            fields = _parse_multipart(data, ctype_full)
        else:
            try:
                fields = dict(parse_qsl(data, keep_blank_values=True))
            except Exception:
                fields = {}
        with self._lock:
            self.posts.append({
                "url": request.url, "host": host, "path": path,
                "ctype": kind, "fields": fields, "raw": data[:4096],
            })

    def _capture_cookies(self, response, host):
        try:
            values = response.header_values("set-cookie")
        except Exception:
            raw = response.headers.get("set-cookie")
            values = raw.split("\n") if raw else []
        for sc in values:
            rec = _parse_set_cookie(sc)
            if not rec:
                continue
            domain = rec["domain"] or host
            with self._lock:
                jar = self.cookies.setdefault(domain, {})
                if rec["name"] not in jar:
                    jar[rec["name"]] = {"has_expiry": rec["has_expiry"]}
                else:
                    jar[rec["name"]]["has_expiry"] |= rec["has_expiry"]

    def _capture_body(self, response, host, path, mime):
        try:
            body = response.body()
        except Exception:
            return
        if not body or len(body) > MAX_BODY_BYTES:
            return
        text = body.decode("utf-8", errors="replace")
        with self._lock:
            self.bodies[response.url] = text
        if "json" in mime:
            self._scan_body_values(host, path, text)

    def _scan_body_values(self, host, path, text):
        """Index EVERY scalar JSON value as a potential body-token candidate."""
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return
        flat = _flatten_json(data)
        with self._lock:
            existing = {(b["host"], b["path"], b["name"]) for b in self.body_values}
        count = 0
        for key, value in flat.items():
            if count >= MAX_KEYS_PER_BODY:
                break
            leaf = re.split(r"[.\[]", key)[-1] or key
            sample = str(value)
            if not leaf or len(sample) < 2:
                continue
            ident = (host, path, leaf)
            with self._lock:
                if ident in existing:
                    continue
                existing.add(ident)
            if isinstance(value, str):
                search = f'"{leaf}":"([^"]*)'
            else:
                search = f'"{leaf}":([^,}}\\s]+)'
            with self._lock:
                self.body_values.append({
                    "host": host, "path": path, "name": leaf,
                    "sample": sample[:24], "search": search,
                    "tokenish": bool(TOKENISH_RE.search(leaf)),
                })
            count += 1

    # ---- analysis helpers (called after capture ends) -------------------

    def hosts(self):
        """Ordered unique hostnames observed."""
        seen, out = set(), []
        for r in self.requests:
            if r["host"] and r["host"] not in seen:
                seen.add(r["host"])
                out.append(r["host"])
        return out

    def post_fields(self):
        """Deduped POST fields: [{name, sample, ctype, path, host}]."""
        seen, out = set(), []
        for p in self.posts:
            for name, sample in p["fields"].items():
                key = (name, p["ctype"], p["host"], p["path"])
                if key not in seen:
                    seen.add(key)
                    out.append({
                        "name": name, "sample": sample, "ctype": p["ctype"],
                        "path": p["path"], "host": p["host"],
                    })
        return out

    def get_fields(self):
        """Query params as pseudo-fields (ctype='get')."""
        return [{"name": q["name"], "sample": q["sample"], "ctype": "get",
                 "path": q["path"], "host": q["host"]} for q in self.query_fields]

    def auth_url_candidates(self):
        """Paths usable as auth_urls: documents, XHR/fetch, POSTs, redirects, final URL."""
        seen, out = set(), []

        def add(host, path, tag):
            key = (host, path)
            if host and key not in seen:
                seen.add(key)
                out.append({"host": host, "path": path, "tag": tag})

        for r in self.requests:
            if r["method"] == "POST":
                add(r["host"], r["path"], "POST")
            elif r["resource_type"] in ("document", "xhr", "fetch"):
                add(r["host"], r["path"], r["resource_type"])
        for rd in self.redirects:
            add(rd["host"], rd["path"], "redirect")
        if self.final_url:
            fp = urlparse(self.final_url)
            fhost, fpath = fp.hostname, fp.path or "/"
            # retag the existing entry if the final URL was already seen
            for item in out:
                if item["host"] == fhost and item["path"] == fpath:
                    item["tag"] = "final"
                    break
            else:
                add(fhost, fpath, "final")
        return out

    def host_references(self, ref_host, in_hosts):
        """Hosts from in_hosts whose captured bodies mention ref_host."""
        hits = set()
        for url, body in self.bodies.items():
            h = urlparse(url).hostname
            if h in in_hosts and h != ref_host and ref_host in body:
                hits.add(h)
        return sorted(hits)

    def stats(self):
        return {
            "requests": len(self.requests),
            "posts": len(self.posts),
            "post_fields": len(self.post_fields()),
            "query_fields": len(self.query_fields),
            "headers": len(self.req_headers),
            "hosts": len(self.hosts()),
            "cookies": sum(len(v) for v in self.cookies.values()),
            "body_values": len(self.body_values),
        }
