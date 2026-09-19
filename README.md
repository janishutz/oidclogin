# oidclogin
OpenID Connect Login SDK written in Go for Gin.

The following environment variables are expected to be set:
```env
OIDC_CLIENT_ID=<client id>
OIDC_CLIENT_SECRET=<client secret>
OIDC_ISSUE=<issuer url>
```
If these env vars are not present, then depending on configuration, stubs will be used for the endpoints or the program will crash
