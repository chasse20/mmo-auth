# MMO Auth Service

This is a standalone Authentication Service designed to scale regionally and support high-volume player counts (feasibly 1,000,000+). For now, it authenticates Steam users using OpenID 2.0 in general, as well as Steamworks Web API tickets intended for game clients. Each verified Steam identity is resolved to a UUID account in distributed YugabyteDB and issues signed access and refresh tokens.

The service would be isolated from and used independently of any actual game backend, and is only responsible for approving access to the public edges (e.g., SDR or a web API). Both Steam authentication methods use the same account and token infrastructure. Note that this repository serves as just a foundation for a much wider project and lacks more mature features necessary for production environments such as moderation, alternative providers, filters, etc.

- Tokio and Axum for asynchronous HTTP hosting and graceful shutdown
- Steam OpenID 2.0 for browser clients
- Optional Steamworks Web API ticket authentication for game clients (Unreal, Unity, etc.)
- SQLx and YugabyteDB for account storage, refresh tokens, distributed scaling, automatic migration, and replay protection
- JWT access tokens with JWKS public-key publication
- Opaque refresh tokens, hashing, rotation, and family revocation
- Protobuf request/response contracts over HTTP
- Strict environment configuration, readiness checks, and scheduled cleanup

## Flow

```text
Browser                  Auth Service                  Steam/YugabyteDB
   |                          |                                 |
   +--- GET /auth/steam/start +---- OpenID redirect ----------> Steam
   |                          |                                 |
   +--- OpenID callback ----->+---- verify assertion ----------> Steam
   |                          +---- resolve SteamAccount ------> YugabyteDB
   |                          +---- create one-time exchange --> YugabyteDB
   +<-- exchange cookie ------+
   |
   +--- POST /auth/exchange ->+---- issue JWT + refresh -------> YugabyteDB
   +<-- TokenResponse --------+

Game client             Auth Service                  Steam / YugabyteDB
   |                          |                                 |
   +--- Steamworks ticket --->+---- AuthenticateUserTicket ----> Steam
   |                          +---- resolve SteamAccount ------> YugabyteDB
   |                          +---- reject ticket replay ------> YugabyteDB
   +<-- TokenResponse --------+
```

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /auth/steam/start` | Steam OpenID login redirect |
| `GET /auth/steam/callback` | Steam OpenID response verification |
| `GET /auth/steam/complete` | Minimal browser completion page |
| `POST /auth/steam/ticket` | Native Steamworks ticket authentication (optional) |
| `POST /auth/exchange` | Exchange an HttpOnly login credential for a token pair |
| `POST /auth/refresh` | Rotate refresh token; issue new token pair |
| `POST /auth/revoke` | Revoke a refresh-token family |
| `POST /auth/validate` | Validate signed access JWT |
| `GET /.well-known/jwks.json` | Publish trusted public verification key |
| `GET /health/live`, `/health/ready` | Process and database readiness |

### Protobuf

All request and response messages live in **`proto/auth.proto`**

The native request includes the **raw Steam ticket bytes** obtained from Valve's `GetAuthTicketForWebApi`

```protobuf
message AuthenticateSteamTicketRequest {
  bytes ticket = 1;
}
```

A successful ticket verification or login exchange returns `TokenResponse`, which contains the JWT access token, opaque refresh token, expiration duration, and account UUID. The server uses HTTP with Protobuf bodies. Steam OpenID redirects and JWKS responses remain ordinary HTTP/JSON as appropriate.
