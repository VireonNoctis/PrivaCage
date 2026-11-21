# PrivaCage web deployment

The website is a static Svelte 5/Vite build. The API is a separate Rust/Axum process.
There is no Next.js server and no React/TSX component tree in this deployment.

## Build

From the repository root:

```sh
cd apps/web
npm ci
npm run check
npm test
npm run build
```

Publish `apps/web/dist/` as the static document root. Vite copies `apps/web/public/404.html`
to `dist/404.html`. Configure the hosting service to use that file as its not-found page
and to return HTTP 404 rather than a successful 200 for missing paths. In local Vite
development, the SPA entry handles unknown pathnames and renders the Svelte 404 component.

## Rust API configuration

The backend binds to `127.0.0.1:8787` by default. It reads environment variables directly;
it does not parse dotenv files. Use the values in `web-backend/.env.example` as a template
for your process manager/container environment.

Defaults:

- `PRIVACAGE_RATE_LIMIT_REQUESTS=120`
- `PRIVACAGE_RATE_LIMIT_WINDOW_SECONDS=60`
- `PRIVACAGE_TRUSTED_PROXY_IPS=` (empty; no proxy header is trusted)

The API applies an in-memory sliding-window limit per observed peer IP. It covers all API
routes, including unknown-route responses, and returns HTTP 429 with `Retry-After` and
`RateLimit-*` headers. The client bucket table is bounded. Because the limiter is local
to one process, its counters reset on restart and are not shared across multiple API
replicas. It is an application abuse-control layer, not a DDoS mitigation service; use
the hosting provider or edge proxy for volumetric traffic controls.

### Reverse-proxy trust

Do not set `PRIVACAGE_TRUSTED_PROXY_IPS` merely because a deployment has a proxy. Add
only the exact peer IP addresses from which the Rust process receives proxy connections.
Every trusted proxy must overwrite `X-Real-IP` with the address observed on its own
client connection. The backend ignores `X-Real-IP` from all other peers. Do not forward
a client-supplied value unchanged.

An example Nginx configuration is in [nginx-privacage.conf](nginx-privacage.conf).
Review its addresses, TLS termination and static document root for the actual deployment
before using it.

## 404 behavior

- Unknown website paths render the Svelte `NotFound.svelte` page in SPA development/fallback mode.
- Static hosting receives `dist/404.html` as the custom 404 document.
- Unknown API paths return a JSON `not_found` response with HTTP 404; they do not return the website HTML page.
