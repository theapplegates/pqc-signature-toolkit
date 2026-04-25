# Winternitz Signature Toolkit

Browser-based OpenPGP v6 signing and verification using the Sequoia-PGP WASM build vendored in `vendor/sequoia-wasm`.

## Local Development

```bash
npm install
npm run dev
```

## Netlify

This repo is self-contained for Netlify builds. The generated WASM package is vendored so Netlify does not need a sibling `../sequoia-wasm` directory.

Build settings:

- Build command: `npm ci && npm run build`
- Publish directory: `dist`
- Node version: `20`

These are already set in `netlify.toml`.

## Optional Verifier Gate

Set these environment variables in Netlify to require a small login before using the Verify tab:

```bash
VITE_VERIFIER_LOGIN_REQUIRED=true
VERIFIER_USERNAME=verifier
VERIFIER_PASSWORD=change-me
```

The username and password are checked by a Netlify Function, so the password is not bundled into browser JavaScript. This is still intentionally small authentication. For full account management, use Clerk or another hosted auth provider.
