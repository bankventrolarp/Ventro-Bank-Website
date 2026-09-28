# Ventro Bank Website

Independent Ventro Bank website and backend architecture.

## Frontend

- GitHub Pages compatible static frontend
- Near-black / emerald Ventro Bank visual identity
- Responsive desktop, tablet, and mobile layout
- Public legal, support, community, app, store, account, downloads, subscription, and admin UI
- No Base44 runtime dependency
- No Supabase
- No secrets in frontend code

The frontend intentionally does **not** pretend that account, payment, download, email, or admin features work before the secure backend is configured. `config.js` contains a blank `backendApiUrl` until the Cloudflare Worker is deployed.

## Purchase model

Ventro Bank is a CA$10 one-time purchase. Stripe Checkout handles payment. Download entitlement is granted only from a server-side verified Stripe webhook.

The APK itself does not require another purchase.

## Backend architecture

`worker/` contains the Cloudflare Workers architecture:

- Cloudflare Worker API
- Cloudflare D1 database schema
- Cloudflare R2 protected APK storage
- Secure account sessions
- Password reset flow
- Stripe Checkout
- Stripe webhook signature verification
- Purchase entitlement records
- Optional Ventro Bank Updates subscription
- Stripe Customer Portal
- Server-side admin authorization
- Protected APK downloads
- Release publishing endpoint
- Update publishing and subscriber email architecture

### Required services

1. GitHub Pages for the frontend
2. Cloudflare Workers for the backend
3. Cloudflare D1 for account/purchase/subscription/release records
4. Cloudflare R2 for APK release storage
5. Stripe for the CA$10 purchase and optional update subscription
6. A transactional email provider such as Resend for password reset and update emails

### Deployment setup

1. Create a Cloudflare Worker.
2. Copy `worker/wrangler.toml.example` to your local `wrangler.toml` and replace the D1 database ID and R2 bucket name.
3. Apply `worker/schema.sql` to the D1 database.
4. Create the CA$10 one-time Stripe Price and set `STRIPE_PRICE_ID`.
5. Optionally create the separate Ventro Bank Updates recurring Stripe Price and set `STRIPE_SUBSCRIPTION_PRICE_ID`.
6. Configure a Stripe webhook pointing to `/stripe/webhook` and set `STRIPE_WEBHOOK_SECRET` as a Worker secret.
7. Set `STRIPE_SECRET_KEY` as a Worker secret.
8. Set `RESEND_API_KEY` and a verified `EMAIL_FROM` as Worker secrets/vars.
9. Set `ADMIN_EMAIL` to `bankventrolarp@gmail.com`.
10. Deploy the Worker.
11. Put the Worker URL into `config.js` as `backendApiUrl`.
12. Keep all secrets in Cloudflare Worker secrets. Never commit them.
13. Test signup, login, logout, password reset, Stripe Checkout, webhook entitlement, protected download, subscription management, and admin authorization before production use.

## Important production note

The repository contains the secure backend architecture and frontend integration, but it is **not production-ready until the external Cloudflare, Stripe, R2, D1, and email provider credentials/services are actually configured and tested**.

No frontend URL, success page, localStorage value, or cookie alone grants a purchase entitlement. Only the verified Stripe webhook records a paid purchase.

## Brand / product disclaimer

Ventro Bank is a fictional banking simulator for LARP, roleplay, and entertainment. It uses fictional money only and does not provide real banking, deposits, withdrawals, loans, investments, money transfers, or other real financial services.
