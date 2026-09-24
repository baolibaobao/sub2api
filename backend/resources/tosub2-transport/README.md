# Sub2API toSub2 transport helper

This directory contains the small runtime subset adapted from `poxiao33/toSub2`
for the OpenAI OAuth protocol login and token transport:

- `tls_transport.py` keeps one `curl_cffi` session, proxy and Chrome TLS profile.
- The Go protocol provider uses that session for the normal ChatGPT password + TOTP
  flow, workspace selection and Codex OAuth callback.
- `cloudflare-ctf/` runs the parent challenge and Turnstile child runtime and
  returns the clearance to the same Python session.

Sub2API starts this helper only when
`OPENAI_OAUTH_TOSUB2_TRANSPORT_ENABLED=true` (or the legacy
`OPENAI_REAUTH_TOSUB2_TRANSPORT_ENABLED=true`) is set. The Go side speaks the
same newline-delimited JSON protocol used by toSub2 and limits request frames,
challenge bodies and response bodies. Credentials, cookies and tokens stay in
the helper process memory and are never logged by Sub2API.

## Runtime requirements

The helper is optional and is not required for the normal Sub2API image:

- Python 3.9+ with `curl_cffi==0.15.0`.
- Node.js 20+ with `jsdom==26.1.0` available through `NODE_PATH` or the normal
  `node_modules` lookup path.

Set `OPENAI_OAUTH_TOSUB2_PYTHON` and `OPENAI_OAUTH_TOSUB2_NODE` when the
executables are not named `python3` and `node`. Keep the helper disabled until
those dependencies have been installed and verified in the same container.

The repository Dockerfile has an opt-in build switch that installs these
dependencies into the image without changing the default image:

```text
docker build --build-arg INCLUDE_TOSUB2_RUNTIME=true -f deploy/Dockerfile .
```

Use the resulting custom image in Compose before setting
`OPENAI_OAUTH_TOSUB2_TRANSPORT_ENABLED=true`; the published `weishaw/sub2api`
image does not include this optional runtime.

The automatic reauthorization path does not start Chromium or scrape the login
page. It uses the official JSON endpoints in one browser-like session. Every
protocol request is checked for a Cloudflare challenge. When a supported
challenge is returned, the helper runs the solver in the same session and
replays the exact request with the same proxy, TLS profile and cookies. If the
challenge remains, the provider reports `security_challenge_required`; an
ordinary `auth.openai.com/log-in` HTML page is still reported as a
protocol/login-state error instead of being misclassified as Cloudflare.

## Attribution

The copied transport and challenge-runtime subset is derived from the MIT
licensed `poxiao33/toSub2` project, version `v1.7.1`. The upstream license is
kept in the repository root at `THIRD_PARTY_NOTICES/toSub2-MIT.txt`.
