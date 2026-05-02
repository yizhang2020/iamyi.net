# iamyi.net

`iamyi.net` is my personal profile site and a collection of my personal writings about security.

The content here is primarily focused on application security, cloud security, GenAI and ML security, security architecture, and related research notes.

## License

Unless otherwise noted, the original writing in this repository is licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).

See <https://creativecommons.org/licenses/by/4.0/> for the license terms.

## Technical Choices

This site is built as a lightweight Markdown-based documentation site.

- Content lives in `docs/` as Markdown files.
- Source and reference materials live in `materials/` and should be treated as read-only.
- The local development server is run with **`mkdocs serve`** (same engine as `./build-site.sh`).
- `./start.sh` activates `.venv`, installs dependencies if needed, and runs `mkdocs serve` (default `127.0.0.1:8000`; override with `MKDOCS_DEV_ADDR`). Live reload watches `docs/` and `mkdocs.yml`.
- You can still run `zensical serve` manually if you prefer; production builds use `mkdocs build`.

## Rebuild A Similar Site

1. Create a repository with a `docs/` directory for Markdown content.
2. Add a site configuration file, such as `mkdocs.yml`, for your documentation framework.
3. Install the required tools:

```bash
pip install zensical
brew install fswatch
```

4. Add or adapt `start.sh` to run the local server:

```bash
./start.sh
```

5. Write pages in `docs/` and update the site navigation in `mkdocs.yml`.

6. Keep private notes, PDFs, drafts, and source references outside the published content path unless they are intended to be published.

## Local Development

Run:

```bash
./start.sh
```

The script runs **`mkdocs serve`** so the preview matches the static build. If the page looks blank or styles are missing, do a full build once (`./build-site.sh`) and hard-refresh the browser; avoid opening `site/index.html` via `file://` (use `http://127.0.0.1:8000/` instead).

## GitHub Pages

Production builds use **`mkdocs build`** (see `.github/workflows/deploy.yml` and `./build-site.sh`). In the repo **Settings → Pages**, set **Source** to **GitHub Actions**, not “Deploy from a branch.” If Source points at the branch root, GitHub serves files from the repo (where there is no `index.html`), which often looks like only **`README.md`** instead of the built site under `site/`.

The home page **Latest writing** table is refreshed from your docs by `tools/gen_latest_writing.py` before each build (`./start.sh`, CI). YAML front matter (`title`, `keywords`, `description`) keeps titles and summaries tidy.
