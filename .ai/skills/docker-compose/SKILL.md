---
name: docker-compose
description: Manage Docker Compose service definitions, networking, volumes, healthchecks, and service dependencies. Use when adding/modifying services, changing ports, or updating container configuration.
---

# Docker Compose

## Tool integration
- Use [references/service-map.md](./references/service-map.md) for the current service topology and port assignments.
- Use [references/volume-mounts.md](./references/volume-mounts.md) for mount points and read-only constraints.

## Workflow
1. Review current `docker-compose.yml` before making changes.
2. Validate port assignments don't conflict with existing services (see [references/service-map.md](./references/service-map.md)).
3. Ensure healthchecks are defined for new services.
4. Verify dependency ordering with `depends_on` and `condition: service_healthy`.
5. Run `docker-compose config --quiet` to validate syntax.
6. Test with `docker-compose up -d` and check logs for errors.

## Guardrails
- Do not expose services on privileged ports (< 1024) unless mapping from higher host ports.
- Do not use `network_mode: host` — keep services on the default bridge network.
- Do not add `restart: always` — use `restart: unless-stopped` for dev environments.
- Do not store secrets in docker-compose.yml beyond dev-only defaults.

## Done criteria
- `docker-compose config --quiet` passes without errors.
- All services start and pass healthchecks.
- No port conflicts with existing services.
