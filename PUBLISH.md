# Publishing checklist

Not part of the package — delete this file before or after publishing, your
choice. It exists so the push is a checklist rather than a decision.

## Pre-flight — done 2026-08-12

- [x] Secret scan of all tracked files — clean. No API key in any committed
      file; `.env` is gitignored and untracked.
- [x] `mcp` dependency pinned `<2`. **This was a live break:** `mcp>=1.2.0`
      resolved to 2.0.0, which removed `mcp.server.fastmcp`, so a fresh
      `pip install -e .` failed on import. Fixed in `requirements.txt` and
      `pyproject.toml`.
- [x] Test suite verified on a clean install: **26 passed**.
- [x] `LICENSE` added (MIT was claimed in the README and `pyproject.toml` but
      no license file existed).
- [x] Git identity is the GitHub noreply address, not a personal one.

## Still to do — you

- [x] Contact address set to `aryan.kshir10@gmail.com` across `README.md`,
      `content/services/OFFER.md`, `DEEP-case-study.md` and
      `OUTREACH-urlscan.md`. The Darkmatter8 pitch deliberately still carries a
      separate token — it must never use this address.
- [ ] Decide the `LICENSE` copyright holder. It currently says
      `blackhole8080-darkmatter`. Your legal name is the more conventional
      choice and is not a privacy problem on this account, which is already
      real-name linked — but it is permanent and public, so it is your call.

## Publish

`gh` is not installed on this machine. Either install it:

```bash
winget install --id GitHub.cli
```

then, from `urlscan-mcp/`:

```bash
git add -A && git commit -m "Pin mcp<2, add LICENSE and contact" && gh repo create urlscan-mcp --public --source=. --remote=origin --push
```

Or create the repo through the GitHub web UI (empty, no README, no license,
no .gitignore) and push to it:

```bash
git add -A && git commit -m "Pin mcp<2, add LICENSE and contact" && git remote add origin https://github.com/blackhole8080-darkmatter/urlscan-mcp.git && git branch -M main && git push -u origin main
```

## After the push

1. Open the repo in a logged-out browser window. Confirm the README renders,
   the contact line is a real address, and nothing unexpected is in the tree.
2. Clone it fresh into a temp directory, `pip install -e .`, `pytest`. If it
   passes there, the email's central claim is true for the reader too.
3. Only then send the pitch in `content/services/OUTREACH-urlscan.md`.

Step 2 is not optional. The whole pitch rests on "I'd rather just send it
working", and a stranger's first move will be to install it.
