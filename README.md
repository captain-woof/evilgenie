# evilgenie — Evilginx phishlet generator

Opens a browser at a target login page, captures the **entire** auth flow while
you perform it by hand, then interactively builds an Evilginx v3 phishlet YAML
from whatever was observed.

## Installation

```
pip3 install --break-system-packages virtualenv
python3 -m virtualenv venv
source ./venv/bin/activate

pip3 install -r requirements.txt
playwright install firefox
```

## Usage

```
python3 main.py -u https://target.com/login [-o ./phishlets]
```

1. A browser opens at the login page and **stays open**. Perform the full
   authentication flow (username → password → OTP/MFA → post-login landing).
2. Come back to the terminal and press **ENTER** — the browser closes and the
   capture ends.
3. Interactive menus (arrow keys, **SPACE** to toggle, **ENTER** to confirm)
   let you pick exactly what goes into the phishlet. **First you pick the
   domains/subdomains to proxy** — every later menu is then scoped to only
   those chosen hosts:
   - **proxy_hosts** — every domain/subdomain observed (picked first)
   - **landing host** — which host phishing URLs point at
   - **session hosts** — which hosts carry the session
   - **auth_tokens** — cookies, JSON body tokens, HTTP request headers
   - **credentials** — username / password / custom fields (form, JSON, multipart, query)
   - **auth_urls** — post-auth paths that trigger a successful capture
4. Subdomains and domains are split and substituted correctly in the phishlet
   (`orig_sub` / `domain` in `proxy_hosts` and `sub_filters`), and
   `sub_filters` are auto-derived from host references observed in captured
   response bodies.
5. The phishlet YAML is written to the output directory and printed.

## What gets captured

Everything, in all formats — nothing is pre-filtered out of the menus:
hosts, query params, POST fields (form / JSON / multipart), request headers,
Set-Cookie cookies, response bodies (text mimes), redirects, and JSON body
values. Token-ish items are only *preselected* for convenience.

## Test web app

`test-web-app/` is a local Flask + SQLite app with a multi-step login that
spans **two root domains** and several subdomains, to exercise the generator's
host-scoping and sub/domain substitution:

- **myapp.test** — `www` (landing/email), `auth` (password/OTP), `api` (JSON), `static`
- **cdn-corp.test** — `cdn` (JS), `assets` (images), `media` (unused)

The login flow crosses subdomains and both root domains (www → auth → api →
www/dashboard, with JS/assets loaded from the cdn-corp.test domain).

Setup — the app tells you exactly what to add to `/etc/hosts` and waits:

```
cd test-web-app
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
./venv/bin/python3 app.py        # prints the /etc/hosts line, waits for ENTER
```

It prints a line like:

```
127.0.0.1 myapp.test www.myapp.test auth.myapp.test api.myapp.test static.myapp.test cdn-corp.test cdn.cdn-corp.test assets.cdn-corp.test media.cdn-corp.test
```

Add that to `/etc/hosts` (e.g. `sudo nano /etc/hosts`), then press ENTER in the
app's terminal — it re-checks resolution and starts the web server on
`http://127.0.0.1:5000`.

Then run evilgenie against it (no DNS flags needed — the system resolves via
`/etc/hosts`):

```
./venv/bin/python3 main.py -u http://www.myapp.test:5000/ -o ./phishlets-out
```

Demo credentials: `demo@example.com` / `Password123!` / OTP `123456`
