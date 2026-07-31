# Test server

Mock API for `baton-tenable-vm`, used when no real-tenant credentials are
available — in particular when validating the FedRAMP (`fedcloud.tenable.com`)
path without access to a FedRAMP Moderate instance. Replicates Tenable VM's
auth header, endpoints, response shapes, and error envelope from the public
developer docs.

## Auth

| Real API                                                                                                          | Test server                                               |
| ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `X-ApiKeys: accessKey=…; secretKey=…` on every request ([docs](https://developer.tenable.com/docs/authorization)) | Same header                                               |
| Per-user keys generated in the commercial or FedRAMP tenant                                                       | Hardcoded: `test-access-key` / `test-secret-key`          |
| Keys are environment-specific (commercial ≠ FedRAMP)                                                              | Single mock — point the connector at it with `--base-url` |

## Endpoints

| Path                                        | Method           | Doc URL                                                                                                                                                                                                          |
| ------------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/users`                                    | GET, POST        | [users-list](https://developer.tenable.com/reference/users-list) / [users-create](https://developer.tenable.com/reference/users-create)                                                                          |
| `/users/{id}`                               | GET, PUT, DELETE | [users-details](https://developer.tenable.com/reference/users-details) / [users-edit](https://developer.tenable.com/reference/users-edit) / [users-delete](https://developer.tenable.com/reference/users-delete) |
| `/users/{id}/enabled`                       | PUT              | [users-enabled](https://developer.tenable.com/reference/users-enabled)                                                                                                                                           |
| `/groups`                                   | GET              | [groups-list](https://developer.tenable.com/reference/groups-list)                                                                                                                                               |
| `/groups/{id}/users`                        | GET              | [groups-list-users](https://developer.tenable.com/reference/groups-list-users)                                                                                                                                   |
| `/groups/{id}/users/{userId}`               | POST, DELETE     | [groups-add-user](https://developer.tenable.com/reference/groups-add-user) / [groups-delete-user](https://developer.tenable.com/reference/groups-delete-user)                                                    |
| `/access-control/v1/roles`                  | GET              | [access-control-roles-list](https://developer.tenable.com/reference/access-control-roles-list)                                                                                                                   |
| `/access-control/v1/users/{uuid}/roles`     | GET, PUT         | [role-list](https://developer.tenable.com/reference/access-control-users-role-list) / [role-update](https://developer.tenable.com/reference/access-control-users-role-update)                                    |
| `/api/v3/access-control/permissions`        | GET              | [permissions-list](https://developer.tenable.com/reference/io-v3-access-control-permissions-list)                                                                                                                |
| `/api/v3/access-control/permissions/{uuid}` | GET, PUT         | [permissions-details](https://developer.tenable.com/reference/io-v3-access-control-permissions-details) / [permission-update](https://developer.tenable.com/reference/io-v3-access-control-permission-update)    |
| `/health`                                   | GET              | (local)                                                                                                                                                                                                          |

## Seed data

5 users (1 disabled, 1 with no extra groups), 4 groups including the
immutable `All Users` group, 4 roles (3 STANDARD + 1 CUSTOM, with overlapping
assignments), 2 permissions (one with User + UserGroup subjects). See
`seeds.go`.

## Running locally

```bash
# Terminal 1 — start the mock
go run ./cmd/test-server/

# Terminal 2 — point the connector at it with the optional base-url flag
go build -o /tmp/baton-tenable-vm ./cmd/baton-tenable-vm
/tmp/baton-tenable-vm \
  --access-key test-access-key \
  --secret-key test-secret-key \
  --base-url http://localhost:8765 \
  --file /tmp/tenable-sync.c1z
```

The connector defaults to `https://cloud.tenable.com`. Set `--base-url`
to this mock for local tests or to `https://fedcloud.tenable.com` for a
FedRAMP Moderate tenant.

## Curl examples

```bash
# List users (with RBAC roles, matching what the connector requests)
curl -s http://localhost:8765/users?withRoles=true \
  -H 'X-ApiKeys: accessKey=test-access-key; secretKey=test-secret-key' | jq .

# Reject missing credentials
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8765/users

# List roles (raw array per docs)
curl -s http://localhost:8765/access-control/v1/roles \
  -H 'X-ApiKeys: accessKey=test-access-key; secretKey=test-secret-key' | jq .
```

## Known doc ↔ connector drifts surfaced by this mock

These are intentional: the mock follows the **docs**, not the connector
(see create-test-server anti-drift rules).

1. **Group `user_count` vs `users_count`.** Docs
   ([groups-list](https://developer.tenable.com/reference/groups-list))
   serialize `user_count`. The connector model tags the field as
   `json:"users_count"`, so the profile field stays `0` against a
   docs-faithful response. Track as a follow-up — do not "fix" the mock
   to match the connector.
