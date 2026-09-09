# Trivy — frontend scaffold

This is built to drop into the `frontend/` folder you already initialized
with `npx wxt@latest init`. It doesn't replace your existing WXT config
files wholesale — merge the pieces below into what you already have.

## What's here

```
shared/
  types.ts          ← every data shape, extension + website both import from this
  api-client.ts      ← the 3 functions that call the backend, nothing else does

lib/
  messages.ts        ← typed messages passed between content script / background / popup
  checks/
    forms.ts          ← insecure forms + unencrypted credential submission
    mixedContent.ts    ← mixed HTTP/HTTPS content
    sensitiveUrl.ts    ← sensitive info in URLs
    headers.ts         ← security header evaluation (pure fn, called from background.ts)
    index.ts           ← runs everything content-script-level, merges results

entrypoints/
  content.ts          ← runs in the page, does DOM checks, responds to background
  background.ts       ← orchestrates the scan, captures headers via webRequest, calls backend
  popup/
    App.tsx             ← the popup UI
    main.tsx, index.html, styles.css

wxt.config.ts        ← manifest permissions (merge into your existing one, don't overwrite)
.env.example         ← copy to .env, set VITE_BACKEND_URL

API_CONTRACT.md      ← give this to your backend partner first, before any code
```

## Merging into your existing scaffold

1. Copy `shared/`, `lib/`, and the `entrypoints/` files into your existing
   `frontend/` folder, matching the structure above.
2. In your existing `wxt.config.ts`, add the `permissions` and
   `host_permissions` shown in this repo's version, and make sure
   `modules: ["@wxt-dev/module-react"]` is set if you used the plain
   TypeScript template originally.
3. Install what's needed:
   ```bash
   npm install react react-dom
   npm install -D @wxt-dev/module-react @types/react @types/react-dom
   ```
4. Copy `.env.example` to `.env`.
5. Run it:
   ```bash
   npm run dev
   ```
   Then load `.output/chrome-mv3-dev` as an unpacked extension in
   `chrome://extensions` (see earlier notes on this — `npm run dev` does
   not open a browser tab by itself).

## For your backend partner

Send them `API_CONTRACT.md` first. It has the full request/response JSON
for every endpoint, which fields to validate vs. recompute, and the open
question about scan storage that's still unresolved — they should read
that before writing any Go code, not after.

## What's stubbed vs. real

- **Real, working logic:** insecure forms, unencrypted credentials, mixed
  content, sensitive URLs, security headers, the popup UI, message
  passing, the API client.
- **Not built yet:** options/settings page, exposed secrets scanner,
  vulnerable library detector, sensitive storage scanner, website
  dashboard. These all have types already defined in `shared/types.ts` so
  slotting them in later doesn't require touching the schema.
- **Backend-owned, not frontend:** the three active-scan checks
  (reflected input, SQL injection probe, CORS test) only exist as types
  here — the actual probing logic is entirely on the Go side.
