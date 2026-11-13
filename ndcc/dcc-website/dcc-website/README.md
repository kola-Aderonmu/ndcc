# Defence Cyber Command: Website and CMS

A public website with a built-in content management system (CMS), served by a small Node.js server.
There are **no npm dependencies**: you only need Node.js 18 or newer.

```
dcc-website/
├─ server.js          Backend: API, sign-in, uploads, poll, incident reports, static files
├─ public/
│  ├─ index.html      Page shell
│  ├─ css/style.css   Styling (colours are CSS variables at the top)
│  └─ js/app.js       Front end: pages, CMS screens, hero animation
├─ data/              Created at first run: db.json and uploads/ (git-ignored, BACK THIS UP)
├─ Dockerfile  .env.example  .gitignore  package.json
```

## Run it locally
```bash
node server.js            # then open http://localhost:3000
```
Staff login is at `http://localhost:3000/#admin` (there is no CMS link in the menu by design).

**Default login:** `dccadmin` / `Dcc@Admin2026`. The CMS stays locked until you change this
on first sign-in. To skip that, set `ADMIN_PASS` in the environment before the first run.

## What the CMS manages
News & publications, gallery photos, leadership profiles, job listings, downloadable resources,
site settings (hero video/image, headline, contact details, cyber advisory level, poll),
and incident reports submitted through the public form.

## Deploy to the internet (so the public can see it)
1. Push this folder to GitHub (instructions below).
2. Pick a host that runs Node.js and has a **persistent disk** (for `data/`):
   a VPS (Ubuntu + Nginx), Render, Railway, Fly.io, or any Docker host.
3. Start command: `node server.js`. Set `PORT`, `DATA_DIR` (pointing at the persistent disk),
   `ADMIN_PASS`, and `TRUST_PROXY=1`.
4. Point your domain (for example `dcc.gov.ng`) at the host and enable HTTPS (Let's Encrypt or the host's built-in TLS).
   Cookies are marked `Secure` automatically when HTTPS is detected.
5. Back up the `data/` folder regularly.

### Minimal Nginx (VPS) example
```nginx
server {
  server_name dcc.example.gov.ng;
  client_max_body_size 25m;
  location / { proxy_pass http://127.0.0.1:3000; proxy_set_header Host $host;
               proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Proto $scheme; }
}
```

## Push to GitHub
```bash
cd dcc-website
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPO.git
git push -u origin main
```
(Create the empty repository on github.com first.) `data/` and `.env` are git-ignored, so passwords and uploads are never pushed.

## Security notes
- Passwords are hashed with scrypt; sessions use HttpOnly, SameSite=Strict cookies; state-changing calls need a custom header (CSRF defence).
- Login is limited to 5 failed attempts per IP per 15 minutes; poll votes and incident reports are rate limited.
- Uploads are limited to 20 MB, a fixed list of file types, and checked against file signatures; uploaded files are served with `nosniff` and a sandboxing CSP.
- Sessions are stored in memory, so a server restart signs everyone out.
- The page uses inline scripts/handlers, so the Content-Security-Policy allows `'unsafe-inline'`. A future hardening step is moving those to external event listeners.
- Before go-live: run an independent penetration test, add two-factor sign-in, and consider a managed database.
- The crest, contact details and sample content are placeholders. Replace them with approved official material.
