

# Build & Publish Instructions (Zensical → GitHub Pages → Custom Domain)

## 1. Set up local environment

Install Python and create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Your `requirements.txt` should include:

```text
zensical
mkdocs-material
pymdown-extensions
```

---

## 2. Initialize and run Zensical site

Start local development server:

```bash
zensical serve
```

Access locally:

```text
http://127.0.0.1:8000
```

---

## 3. Build the static site

Run:

```bash
zensical build --clean
```

This generates:

```text
site/
```

This `site/` folder is what gets deployed.

---

## 4. Prepare GitHub repository

Create repo (ignore if you already done):

```text
iamyi.net
```

Push your code:

```bash
git init
git add .
git commit -m "Initial site"
git branch -M main
git remote add origin https://github.com/<username>/iamyi.net.git
git push -u origin main
```

---

## 5. Add GitHub Actions deployment

Create file:

```text
.github/workflows/deploy.yml
```

Use the version checked into this repository (summary: `checkout` with full git history, `pip install`, `mkdocs build --clean`, verify `site/index.html`, `upload-pages-artifact` with `path: site`, then `deploy-pages`). The workflow must grant **`actions: write`** on the build path so the Pages artifact can upload when you set restrictive top-level permissions.

---

## 6. Enable GitHub Pages

Go to:

```text
Repo → Settings → Pages
```

Set:

```text
Source: GitHub Actions
```

**Troubleshooting — the live site only shows `README.md`:** almost always means Pages is still publishing the **repository branch** (for example **Deploy from a branch → `main` → `/ (root)`**), which has no `index.html` at the repo root, so GitHub falls back to rendering the README. Switch **Build and deployment → Source** to **GitHub Actions**, save, then re-run the workflow (push a commit or use **Actions → Deploy Site → Run workflow**). Wait until the **deploy** job finishes and the environment shows the new deployment.

After deployment, your site is available at:

```text
https://<username>.github.io/iamyi.net/
```

---

## 7. Configure custom domain (www version)

In:

```text
Settings → Pages
```

Set:

```text
Custom domain: www.iamyi.net
```

GitHub will create a `CNAME` file containing:

```text
www.iamyi.net
```

---

## 8. Configure DNS records

Go to your domain provider.

### A records (root domain)

```text
@ → 185.199.108.153
@ → 185.199.109.153
@ → 185.199.110.153
@ → 185.199.111.153
```

---

### CNAME record (www)

```text
www → <username>.github.io
```

Example:

```text
www → yizhang2020.github.io
```

---

## 9. Wait for DNS propagation

Typical time:

```text
5–30 minutes
```

Verify:

```bash
dig www.iamyi.net
```

Should return:

```text
CNAME → <username>.github.io
```

---

## 10. Enable HTTPS

Go back to:

```text
Settings → Pages
```

Enable:

```text
☑ Enforce HTTPS
```

---

## 11. Final production URLs

Your site will now be accessible at:

```text
https://www.iamyi.net   (primary)
https://iamyi.net       (redirect)
```

---

## 12. Update site configuration (important)

In `mkdocs.yml`:

```yaml
site_url: https://www.iamyi.net
```

This ensures:

* correct canonical URLs
* better SEO ranking
* proper link generation

---

## 13. Daily workflow

After setup, your workflow becomes:

```bash
# make changes
git add .
git commit -m "update content"
git push
```

GitHub Actions will:

```text
build → deploy → update site automatically
```

---

## 14. Optional improvements (recommended next)

After MVP:

* add SEO metadata (Open Graph, structured data)
* add CSP/security headers (via Cloudflare later)
* migrate premium site to Cloudflare Pages
* add analytics (privacy-friendly)

---

# Final mental model

```text
Zensical → builds static site
GitHub Actions → deploys site
GitHub Pages → hosts site
DNS → points your domain to GitHub
```
 
