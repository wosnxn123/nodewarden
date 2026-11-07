# Vaultwarden compatibility work

## Scope and reference

This branch is an **in-progress NodeWarden implementation**, not a Vaultwarden release or a claim of complete compatibility.

- NodeWarden base: 1.8.1, upstream commit `fbc0e65df8f405c3120887569e939d615ab68229`.
- Protocol reference: [Vaultwarden 1.37.5](https://github.com/dani-garcia/vaultwarden/releases/tag/1.37.5), reference tree `6ed6921cc2b0e03b4d74189574d2a5e71c512e97`.
- Keep NodeWarden's Workers, D1, R2/KV and custom web vault. Do not substitute the Vaultwarden version number for NodeWarden's application or advertised protocol version.
- Implement behavior independently. Vaultwarden's AGPL-3.0 source is a reference, not code to copy into this LGPL-3.0 project without considering licensing obligations.

## Implemented in this milestone

### Organizations and access

- Organizations, collections, members and group-based collection grants in relational storage.
- Organization creation, settings, collection/group CRUD, and member invitation, acceptance, confirmation, revocation, restoration and removal APIs.
- Owner/admin/user/manager role handling, confirmed-membership checks, union of direct and group grants, and protection of the last confirmed owner.
- Per-user folders and favorites for shared items. Read-only members can change their own preferences without editing the shared ciphertext.
- Server-derived ownership and permissions. Opaque client fields do not grant membership, access or ownership.
- Collection reassignment preserves links the acting user cannot see and rejects removal of visible read-only links.
- Organization events and durable revision/notification fanout. Retry processing has explicit work and time budgets.

### Encryption, sharing and attachments

- Client-generated organization keys, per-member RSA wrapping, and organization-aware item/attachment decryption and encryption.
- Organization keys remain in memory in the custom web vault; lock/logout/revocation clear the corresponding state and decryption worker.
- Personal-to-organization sharing preserves item IDs and checks the original ciphertext, revision and attachment snapshot in the write transaction. Unsupported reverse/cross-organization transfers are rejected.
- Content updates use optimistic concurrency and update attachment key/name metadata atomically with ciphertext.
- Downloads carry a requesting-user-bound, one-time token and check current authorization after consumption. Read-only access does not permit uploads or metadata changes.
- Metadata deletion precedes blob cleanup; failures do not authorize deleting organization data through a personal account operation.
- Bulk sharing returns explicit per-item success/error information for partial outcomes; it does not pretend independent item commits can be rolled back together.

### Lifecycle, migration and backup

- KDF changes with fresh password proof, client-provided rewrapped user key and session revocation.
- Personal vault purge and self-account deletion, preserving organization assets and the last active administrator/organization-owner invariants.
- Key/password updates compare original key/verifier state. Replacing an existing RSA identity while active organization memberships exist is rejected until a coordinated rotation protocol is implemented.
- Runtime and initial schemas agree; migration tests cover existing personal records, attachments, rollback and repeated/concurrent initialization.
- New instance backups use **format v2** with organization tables. Existing v1 personal backups remain supported. Unknown/incomplete organization archive formats are rejected rather than partially restored.
- All exported SQL tables are read in one D1 batch snapshot. Runtime notification state and authentication secrets that are intentionally excluded remain excluded.

### Custom web vault

- Organization creation, collection management, member invitation/acceptance/confirmation and access controls.
- Sharing personal items and changing collection assignments.
- Organization-aware synchronization, permissions, encrypted cache metadata and key selection.
- Hidden-password restrictions are applied in the UI without overwriting the original encrypted secrets during unrelated edits.
- Updated standalone locale bundles in all ten languages.

## Not completed or not yet verified

| Capability | Status |
|---|---|
| Complete official desktop, extension, mobile and CLI interoperability | Not certified by this milestone; requires a pinned, real-client test matrix |
| Email delivery and emailed organization invitations | Not implemented; invitations currently appear in the invited account, and existing registration restrictions still apply |
| Organization groups management UI | Backend support exists; complete management UI still pending |
| Organization deletion UI / password confirmation dialog | Backend requires fresh proof; custom web UI still pending |
| Full organization import/export UX and all reference payload variants | Pending; instance backup is a separate feature |
| Organization policies and organization account recovery | Pending; unsupported capabilities are not advertised as enabled |
| Emergency access | Pending |
| OIDC SSO and SSO enrollment/unlock integration | Pending |
| Directory Connector machine credentials and import | Reference protocol investigated; implementation pending |
| SCIM 2.0 | Pending extension; Vaultwarden 1.37.5 does not expose native SCIM routes and advertises `useScim=false` |
| Email 2FA, Duo, Send email verification and email-change workflows | Pending |
| Coordinated account/organization RSA key rotation | Pending; unsafe partial identity replacement is rejected |
| Complete remote D1 migration and R2/KV deployment acceptance | Pending; no production deployment or production-data test was performed |

Notification fanout processes at most 32 recipients per invocation with a 10-second soft budget. Larger backlogs remain durable but may wait for a later mutation or the next five-minute cron; immediate notification of every member is not guaranteed. Online authorization is rechecked independently of notification delivery.

Revocation stops subsequent authorized online reads and downloads. **It cannot erase plaintext, exported data, or decryptable offline data that a member already obtained.** Password hiding is a client-side restriction, not a cryptographic separation of secrets shared under the same key.

## Verification

Use Node **24.22.1** from `.node-version`. Follow `CONTRIBUTING.md` when changing dependencies or regenerating the lockfile.

```sh
npx tsc -p tsconfig.json --noEmit
npx tsc -p webapp/tsconfig.json --noEmit
npm run build
npm run i18n:validate
npm run test:organizations
npm run test:account-lifecycle
npm run test:config-compatibility
npm run test:vault-compatibility
npm run test:web-crypto
npm run test:notifications-security
npm run test:webauthn-connectors
git diff --check
```

The organization suites use the production schema with a foreign-key-enabled SQLite D1 adapter, including transactions, concurrency interleavings, backup roundtrips, member revocation and cross-organization denial cases. They supplement, not replace, real D1 and official-client acceptance tests.

A local-only Wrangler/Edge browser smoke test has exercised registration, login, organization creation and encrypted initial-collection display using isolated local D1/R2 test data. No production database, real user vault or external identity provider was used. Further cross-user UI and official-client acceptance remain necessary.

## Next milestones

1. Complete the organization UI and real-client acceptance matrix before marking organizational compatibility complete.
2. Add mail delivery and account/MFA workflows, then emergency access and organization recovery with explicit key-lifecycle tests.
3. Add OIDC and Directory Connector using authenticated, scoped identities; provider metadata must never silently become vault-key or membership authority.
4. Add SCIM as a clearly labeled extension of the same member/group lifecycle.

Each milestone should retain an explicit implemented/pending/verified record and pass both positive and denial-path tests before release.
