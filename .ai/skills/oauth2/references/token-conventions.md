# Token Conventions

The mock OAuth2 server uses token prefixes to determine introspection responses:

| Token Pattern        | Introspection Result     | Use Case                 |
|----------------------|--------------------------|--------------------------|
| `valid-<user>`       | `active: true`           | Successful authentication|
| `expired-<user>`     | `active: false`          | Expired token testing    |
| `scope-<user>`       | Insufficient scope error | Scope validation testing |
| Anything else        | `active: false` (invalid)| Invalid token testing    |

## Examples

```bash
# Valid token
curl -X POST http://localhost:8080/introspect -d 'token=valid-dev@local.test'
# → {"active": true, "username": "dev@local.test", ...}

# Expired token
curl -X POST http://localhost:8080/introspect -d 'token=expired-dev@local.test'
# → {"active": false}

# Invalid token
curl -X POST http://localhost:8080/introspect -d 'token=garbage'
# → {"active": false}
```
