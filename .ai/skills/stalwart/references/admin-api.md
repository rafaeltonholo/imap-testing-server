# Stalwart Admin API

Base URL: `http://localhost:8443`
Auth: Basic `admin:secret`

## User Management

```bash
# Create user
curl -u admin:secret -X POST http://localhost:8443/api/principal \
  -H 'Content-Type: application/json' \
  -d '{"type":"individual","name":"dev@local.test","secrets":["dev"],"emails":["dev@local.test"]}'

# List users
curl -u admin:secret http://localhost:8443/api/principal?type=individual

# Get user
curl -u admin:secret http://localhost:8443/api/principal/dev@local.test

# Delete user
curl -u admin:secret -X DELETE http://localhost:8443/api/principal/dev@local.test
```

## Provisioning Authority

Stalwart and Dovecot have independent account authorities. Manage Stalwart
principals through its provider-specific admin flow; do not bulk-copy Dovecot
passwd-file credentials into Stalwart.
