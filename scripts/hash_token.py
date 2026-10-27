#!/usr/bin/env python3
"""Print a new bearer token and the tokens-file line for an actor.

Usage: hash_token.py grokbot
Give the token to the client once; store only the hash on the server.
"""

import hashlib
import json
import secrets
import sys

actor = sys.argv[1] if len(sys.argv) > 1 else "grokbot"
token = secrets.token_urlsafe(32)
print("token (shown once):", token, file=sys.stderr)
print(json.dumps({hashlib.sha256(token.encode()).hexdigest(): actor}))
