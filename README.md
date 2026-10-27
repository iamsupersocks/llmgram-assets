# llmgram-assets

Catalog of free and freemium resources (3D models, textures, audio, datasets,
weights, tools) published on <https://llmgram.app/asset-signal.html>.

One JSON file per resource in `entries/`. Git history is the audit trail:
every addition or correction made through the MCP server is one commit with
its `Operation-Id` and `Actor`.

## What a record holds

| Field | Meaning |
| --- | --- |
| `name`, `summary`, `category`, `tags` | What the resource is |
| `publisher` | Who makes it |
| `resource_url` | Canonical page; it identifies the asset (`id = ast-` + hash of the normalized URL) |
| `download_url` | Direct link to the files, when different |
| `access` | `model` (free, free-with-signup, freemium, open-source, paid, research-only), `license`, `license_url`, `commercial_use`, `signup_required`, `price`, `notes` |
| `procedure` | Ordered steps to get the files |
| `stats` | Count, size, formats, update cadence |
| `source` | Post or page where it was found (author, date, kind) |
| `verdict` | Score 0–100 and why it is worth listing |
| `verification` | Last link check of `resource_url` and `download_url` |
| `status` | `published`, `candidate`, `flagged`, `retired` |
| `flags`, `history` | Reports and the last 50 operations |

## Publication rule

A record is `published` when `access.model` and `access.license` are known,
`procedure` has at least one step, `source.url` is set and its links answer.
Otherwise it is a `candidate`: kept, searchable through the MCP, hidden from
the page, with the list of missing fields. The status is computed, never
supplied by the caller.

`asset_flag` hides a record. An `asset_update` closes `dead_link`, `now_paid`,
`license_changed` and `wrong_info` flags because the update is the
correction. `unsafe` and `duplicate` flags, and `retired`, are cleared only by
a human edit in this repository.

## MCP server

Two entry points share the same tools and rules.

`llmgram_assets.mcp_server` is stdlib-only (Python 3.10+): stdio for a local
agent, or a plain bearer-token HTTP endpoint.

```bash
python3 -m llmgram_assets.mcp_server --local-root . --actor local
```

`llmgram_assets.remote` is the gateway for Grok Bot, which connects to remote
MCP servers through OAuth (discovery, dynamic registration, PKCE). The owner
approves each new client once on `/oauth/approve` with the owner secret;
tokens are signed with a key derived from it, so rotating the secret revokes
every client. Writes go to a clone of this repository and are pushed with a
deploy key scoped to it.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-remote.txt
LLMGRAM_ASSETS_OWNER_SECRET=... \
LLMGRAM_ASSETS_PUBLIC_URL=https://assets-mcp.example \
.venv/bin/python -m llmgram_assets.remote \
  --git-checkout /srv/llmgram-assets --ssh-key /srv/llmgram-assets-deploy-key --port 8791
```

It listens on 127.0.0.1; put it behind a TLS proxy that serves
`LLMGRAM_ASSETS_PUBLIC_URL`. In Grok Bot, add the remote MCP server
`<public URL>/mcp`, then approve the connection on the page it opens.
`deploy/llmgram-assets-mcp.service` is a systemd user unit for it.

Tools: `asset_search`, `asset_get`, `asset_submit`, `asset_update`,
`asset_flag`. Every mutation needs a fresh UUID `operation_id`. An
`ambiguous` result means the write may or may not have landed: retry with the
same `operation_id`, never a new one. Mutations are limited to 120 per hour
per client.

Submitted links are checked from the server: HTTPS only, public addresses
only (checked after DNS resolution, at every redirect), status line only.

## Manual edits

Edit the JSON, then run:

```bash
python3 scripts/validate.py
python3 -m unittest discover -s tests -t .
```
