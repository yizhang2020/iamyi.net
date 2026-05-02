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
- The local development server is run with `zensical serve`.
- `start.sh` wraps the local server and restarts it when the site config changes.
- `fswatch` is used by `start.sh` to watch for config changes.

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

The script starts `zensical serve` and watches `mkdocs.yml` for changes. If your site configuration includes other files, add them to `WATCH_PATHS` in `start.sh`.
