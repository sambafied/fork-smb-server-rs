# `smb-server-backend-shadow`

`smb-server-backend-shadow` is the in-process VFS adapter for Sambafied
per-principal shadow storage.  A backend instance is created by the server for
one configured stable principal; an SMB request cannot choose a principal or a
private storage root.

The underlying store presents a merged namespace over a pinned, immutable base
and private writable state.  Private writes copy up as needed, and whiteouts
hide base entries that the principal has deleted.  Open files use store object
identity handles, so an open object remains identified independently of a path
change.  Manifest and content operations run through a bounded Tokio blocking
pool rather than on the io_uring connection thread.  Store maintenance uses
cross-process leases to coordinate maintenance work.

## Self-contained generic core

This adapter depends on the generic `sambafied-shadow` core checked into this
engine repository.  That source was initially mirrored from the product at
`f93a0fa03dd7d60e805c0aa05dfe3e4769aafa5e` and is currently identical to that
version.  The dependency is an in-repository path dependency; this engine has
no private Git dependency for the generic core.

## Server-owned configuration

The server is implementing `--shadow-config` as JSON.  Its value maps a
lowercase share name to a map of lowercase authenticated SMB user name, then to
the `sambafied-shadow` configuration:

```json
{
  "share-name": {
    "authenticated-smb-user": {
      "root": "/var/lib/sambafied/shadows/user",
      "base": "/srv/sambafied/bases/game-v42",
      "identity": {
        "organization": "example-org",
        "share": "share-name",
        "principal": "stable-principal",
        "base_version": "game-v42"
      },
      "policy": {}
    }
  }
}
```

The configuration is owned by the server and contains no passwords.  It maps an
authenticated SMB user to a server-configured stable principal; request data
does not select the principal, storage root, or base.

## Current boundary

Read, write, create, list, file rename, and delete behavior remains under
implementation and focused testing.  Directory rename is unsupported.  The
adapter rejects persisted timestamps and attributes, extended attributes and
alternate data streams, and ACL setters; it does not silently accept or discard
those requests.  It does not claim Linux ACL passthrough or legacy-client
qualification.

## Narrow live-SMB smoke evidence

A retained Windows fixture has exercised a running modern SMB listener with
two authenticated users.  It verifies Alice's private write and reconnect,
Bob's view of the unchanged base and inability to see Alice's save, host-base
immutability, and SMB1 negotiation rejection.  The recorded engine executable
SHA-256 is `490e1f38e2a136b16d9482aea7e69494bef1f83faa408beb3a0a3303b928c389`.
The fixture checkout fields are unknown, so this is not commit-bound evidence.

See the product's
[`overlay wire evidence`](../../../../docs/overlay-wire-evidence.md) for the
retained reports, exact image digest, fixture method, and the test boundaries.

This narrow smoke does not establish release readiness, vintage-client
interoperability, API, CLI, UI, or complete overlay qualification.  Directory
rename, persisted timestamps and attributes, extended attributes, alternate
data streams, ACL setters, and Linux ACL passthrough remain outside the
qualified scope described above.
