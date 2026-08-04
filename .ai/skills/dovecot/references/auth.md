# Dovecot Authentication

## Shared Eligibility Authority

The authoritative ordinary-user passwd file is generated at
`debug-dashboard/.runtime/dovecot/users` and mounted read-only at
`/etc/dovecot/runtime/users`. Each entry contains one canonical address and a
validated `{ARGON2ID}` provider hash. No ordinary password or passwd authority
is tracked in Git; `config/users.seed` contains addresses only.

The canonical record is `<address>:<provider-hash>::::::`: eight passwd-file
columns (`user`, `password`, `uid`, `gid`, `gecos`, `home`, `shell`, and
`extra_fields`). The six post-password fields are empty because Dovecot
configuration supplies the UID, GID, and home defaults; their delimiters are
still required so passwd-file userdb recognizes the record.

The same runtime file controls ordinary password authentication, userdb
existence, OAuth issuance/introspection through `oauth2-mock`, Postfix
socketmap eligibility, and operator target eligibility.

## Ordinary Dovecot

`config/10-auth.conf` enables `plain`, `login`, `oauthbearer`, and `xoauth2`.

1. The `passwd-file` passdb reads `/etc/dovecot/runtime/users`; it handles
   ordinary PLAIN/LOGIN password verification.
2. The OAuth2 passdb is restricted to XOAUTH2/OAUTHBEARER and posts
   introspection to `http://oauth2-mock:8080/introspect`.
3. The passwd-file userdb reads the same runtime authority and supplies
   UID/GID 1000 plus `/srv/vmail/%{user}`.

The ordinary service does not mount or load the operator master credential.

## Operator Dovecot

The profile-selected operator endpoint enables TLS SASL LOGIN only and uses
this ordered passdb chain:

`operator-master` → `deny-direct` → `eligible-target` → `deny-missing`

1. `operator-master` reads the hash-only
   `/etc/dovecot/operator-auth/master-users`, sets `master = yes`, and uses
   canonical `result_success = continue`. This marks the master password
   verified, jumps to the first non-master passdb, and does not pre-authorize
   the target.
2. Dovecot 2.4.4 retains the Gate 0C behavior first recorded on 2.4.1:
   `auth_preinit` silently omits a first non-master passdb with
   `skip = unauthenticated`. `deny-direct` is therefore the first non-master
   passdb and uses `skip = authenticated`: a verified master continuation
   skips it, while a direct bare-target LOGIN remains unauthenticated and is
   denied there.
3. `eligible-target` uses `skip = unauthenticated`,
   `result_failure = continue-fail`, and
   `result_internalfail = return-fail`. A found target's default `return-ok`
   finalizes success without rechecking the password; a missing target clears
   any prior success and continues; an internal error fails immediately.
4. `deny-missing` denies the missing-target continuation. Both deny passdbs use
   `deny = yes`, `nopassword = yes`, and `nodelay = yes`.

Protected operator identities are absent from the ordinary eligibility/userdb
authority and have no mailboxes. Raw operator secret slots stay in the
unmounted host runtime secrets directory; the operator container receives only
the hash-only master passwd file.
