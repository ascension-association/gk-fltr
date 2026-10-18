# gk-fltr app API (v1)

gk-fltr serves an HTTPS JSON API for a companion app, so a parent can see
usage and change allowances from a phone. It is on by default, on port 8443.

## Configuration

```
-api=:8443                     # default; or specific addresses (repeatable), or off
-api-dir=/perm/gk-fltr/api     # default; holds token, cert.pem, key.pem, settings.json
-api-url=https://router.lan:8443   # optional: the URL the app should use, for the QR code
```

## Home network only

Version 1 works only on the home network. The home network is the subnets
of the router's interfaces **other than its uplinks** (the interfaces that
carry a default route), plus loopback. Link-local IPv6 clients count only on
a home interface. The check follows interface changes within seconds.

Being private isn't enough. Behind an ISP router, the uplink's network is
private too (e.g. 192.168.0.x), and its devices are outside the home.

- Connections from outside the home network are closed as soon as they are
  accepted, before TLS. The app sees a connection reset or a TLS handshake
  failure.
- If one gets through anyway, the request is answered with 403.
- gk-fltr refuses to start with a public `-api` address.

The app should say "connect to your home Wi-Fi" when it can't reach the
router or gets a 403.

Remote access (e.g. through a VPN) is planned for a later version.

## Pairing

On first start gk-fltr creates a random token and a self-signed TLS
certificate in `-api-dir`, and logs a pairing QR code. If the LAN has no
address yet at that point, it logs a reminder instead. To show the QR code
again, run this over breakglass:

```sh
/user/gk-fltr pair                    # QR code in the terminal
/user/gk-fltr pair -png /tmp/pair.png
```

Pass `pair` the same `-api`, `-api-dir` and `-api-url` flags as gk-fltr if
you changed them. The URL in the QR code uses the router's first home
network address. With several LAN interfaces (e.g. a guest network), set
`-api-url` so it uses the right one.

The QR code holds a URI:

```
gkfltr://pair?url=https%3A%2F%2F192.168.1.1%3A8443&token=<64 hex chars>&pin=sha256%2F<base64>
```

| Parameter | Meaning |
|---|---|
| `url` | Base URL of the API, no trailing slash |
| `token` | Bearer token for every request |
| `pin` | SHA-256 of the certificate's public key (SPKI), base64, prefixed `sha256/` |

The app should store the token in encrypted storage (e.g. Android Keystore
and EncryptedSharedPreferences).

To unpair every app, delete `token` in `-api-dir` and restart gk-fltr. The
certificate and its pin stay the same unless you delete `cert.pem` and
`key.pem` as well.

## TLS: trust by pin

The certificate is self-signed and isn't tied to a host name or address, so
the platform's default checks will reject it. The app must:

1. Accept the server certificate only if the SHA-256 of its
   `SubjectPublicKeyInfo` matches the pin, and reject everything else.
2. Skip host name verification. The pin already proves the server's
   identity, and the router's address may change.

With OkHttp, use a custom `X509TrustManager` whose `checkServerTrusted`
compares the leaf certificate's `publicKey.encoded` (which is the DER SPKI)
hashed with SHA-256 against the pin, together with a `HostnameVerifier` that
returns true. Never use a trust-all manager without the pin check. On
Android 9 and later, HTTPS needs no network security config change.

## Requests

- Send `Authorization: Bearer <token>` with every request.
- Request and response bodies are JSON (UTF-8). Request bodies are at most
  64 KiB, and unknown fields are rejected.
- Durations are whole seconds, and times are RFC 3339.
- Errors look like `{"error": "message"}` and use these status codes:

| Code | When |
|---|---|
| 400 | Invalid body or value |
| 401 | Missing or wrong token |
| 403 | Request from outside the home network |
| 404 | Unknown user |
| 429 | 10 failed authentications from this address within a minute; retry after `Retry-After` seconds |
| 500 | Server-side failure, e.g. disk |

## Model

- A **user** is a person who can have several devices. Their devices share
  one **daily allowance** of active YouTube minutes (or of whatever
  `-protocols` lists).
- Users come from two places. The **rules file** (`rules.txt`, edited by hand)
  and the **settings file** (`settings.json`, written by this API). The app's
  device rules apply before the rules file, and an allowance set by the app
  overrides `allow=` in the rules file. Deleting a user through the API removes
  only the app's settings, so a user defined in the rules file remains.
- **Extra time** and **pause** apply until the next daily reset only.
- Changes take effect for new connections at once. Open connections of a
  paused user, or of one whose time ran out, are cut at the next usage
  interval (`-usage-interval`, 1 minute by default).

## Endpoints

### `GET /api/v1/status`

```json
{
  "mode": "queue",
  "fail_closed": true,
  "protocols": ["YouTube", "YouTubeUpload", "YouTubeKids"],
  "started": "2026-10-12T08:00:00Z",
  "time": "2026-10-12T15:00:00Z",
  "uptime_seconds": 25200,
  "next_reset": "2026-10-13T06:00:00Z",
  "rules": {"ip": 1, "mac": 3, "ja4": 0},
  "users": 2
}
```

### `GET /api/v1/users`

Returns all users, sorted by name, as an array of user objects:

```json
{
  "name": "alice",
  "allowance_seconds": 7200,
  "used_seconds": 2580,
  "extra_seconds": 1800,
  "remaining_seconds": 6420,
  "paused": false,
  "managed": true,
  "devices": [
    {"type": "mac", "value": "aa:bb:cc:dd:ee:01", "source": "settings"},
    {"type": "ip",  "value": "192.168.1.23/32",   "source": "rules"}
  ]
}
```

- `remaining_seconds` is `allowance + extra − used`, floored at 0, and 0
  while the user is paused. An `allowance_seconds` of 0 means always blocked
  unless extra time is granted.
- `managed` is true if the user has an entry in the settings file, so
  `DELETE` applies to it.
- Each device's `source` is `settings` (editable through the API) or `rules`
  (only editable in `rules.txt`).

### `GET /api/v1/users/{name}`

Returns one user object, or 404.

### `PUT /api/v1/users/{name}`

Creates or replaces the user's settings:

```json
{
  "allowance_seconds": 7200,
  "devices": [{"type": "mac", "value": "AA:BB:CC:DD:EE:01"}, {"type": "ip", "value": "192.168.1.23"}]
}
```

- `name` may contain letters, digits, `_`, `.` and `-`.
- `allowance_seconds` can be 0 to 86400. `null` or leaving it out means no
  override, so the rules file and `-allowance` decide.
- `devices` replaces the user's settings devices, not their `rules` devices.
  The `type` is `ip` (an address or prefix) or `mac`. Values are normalized,
  as in the example response above.
- At least one of `allowance_seconds` or `devices` is required.

Returns the resulting user object. A device that already belongs to another
user in the rules file now belongs to this user, because the app's rules
apply first.

### `DELETE /api/v1/users/{name}`

Removes the user's settings and returns 204. Returns 404 if the user has
none.

### `POST /api/v1/users/{name}/extra`

```json
{"seconds": 1800}
```

Grants extra time until the next reset and returns the user object.
`seconds` must be non-zero and between −86400 and 86400. A negative value
takes extra time back, but extra time never goes below 0.

### `PUT /api/v1/users/{name}/pause` and `DELETE /api/v1/users/{name}/pause`

`PUT` pauses the user until the next reset, so they have no time left.
`DELETE` resumes them. Both return the user object.

### `GET /api/v1/devices`

Lists clients gk-fltr has seen since it started, newest first, at most 512.
This helps the app pick devices for a user.

```json
[
  {
    "ip": "192.168.1.10",
    "mac": "aa:bb:cc:dd:ee:01",
    "client_label": "Chrome (QUIC)",
    "ja4": "q13d0313h3_55b375c5d22e_4156cdf64688",
    "host": "www.youtube.com",
    "last_seen": "2026-10-12T14:59:31Z",
    "user": "alice",
    "rule": "mac aa:bb:cc:dd:ee:01"
  }
]
```

- `mac` is missing when unknown.
- `client_label` comes from gk-fltr's `-labels` file.
- `user` and `rule` show what the device matches now.
- `host` is from the device's most recent connection and may be any site.

### `GET /api/v1/blocks`

Returns recent entries from the block log (`-block-log`), oldest first. Each
entry has the same form as a line in that file (see the README). The result
is `[]` without a block log.

| Query | Meaning |
|---|---|
| `since` | Only entries after this RFC 3339 time |
| `user` | Only this user's entries |
| `limit` | At most this many of the newest matches, 1 to 1000 (default 100) |

Only the last 1 MiB of the current log file is searched.

Each entry's `reason` is one of:
- `rule`: blocked outright.
- `allowance_exhausted`: the user's time ran out.
- `paused`: the user was paused.

## Polling

The API doesn't push updates. While the app is open, poll `GET /users` every
30 to 60 seconds; use is measured once per usage interval, so faster polling
shows nothing new.
