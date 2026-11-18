# Repository privacy checks

Keep environment bindings, generated access records, account inventories, connection reports, and operator acceptance records local. The repository ignores `env/` and `planning/`; the privacy check also rejects forced additions of those paths and credential files.

Install the native hook with `git config core.hooksPath .githooks`, or use the existing `lefthook install` workflow. Both run the staged privacy check and the existing Gitleaks secret scan. Install Gitleaks v8.24.2 in `.tools/gitleaks` or on `PATH` before committing.

Run `just privacy-staged` to check staged changes, or `just privacy-check` to check all reachable Git history. The privacy check reads staged Git blobs, so unstaged edits cannot hide staged private content. The secret-scan workflow checks the pull-request commit range and all reachable history on pushes and scheduled runs, including records added and later deleted.

The privacy policy rejects known personal and deployment identifiers by SHA-256 digest without printing their values. Add only necessary code or documentation; private operational records belong outside tracked history.
