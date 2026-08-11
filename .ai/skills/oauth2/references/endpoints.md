# OAuth2 Mock Endpoints

Base URL: `http://<host>:8080`, where `<host>` is `localhost` for clients on
the development machine or that machine's LAN address for another test device.
The discovery document derives its absolute endpoint URLs from the validated
HTTP `Host` authority used for the request.

| Endpoint       | Method | Purpose                                |
|----------------|--------|----------------------------------------|
| `/health`      | GET    | Health check (used by Docker)          |
| `/.well-known/oauth-authorization-server` | GET | Discovery metadata |
| `/authorize`   | GET    | Authorization page (shows consent UI)  |
| `/token`       | POST   | Token exchange (auth code + refresh)   |
| `/introspect`  | POST   | Token introspection (RFC 7662)         |

## Query Parameters (any endpoint)

| Parameter | Effect                                         |
|-----------|-------------------------------------------------|
| `?delay=<seconds>` | Adds artificial latency to the response |
| `?status=<code>`   | Forces a specific HTTP status code      |
