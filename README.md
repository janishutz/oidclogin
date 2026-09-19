# oidclogin
OpenID Connect Login SDK written in Go for Gin.

The following environment variables are expected to be set:
```env
OIDC_CLIENT_ID=<client id>
OIDC_CLIENT_SECRET=<client secret>
OIDC_ISSUE=<issuer url>
```
If these env vars are not present, then depending on configuration, stubs will be used for the endpoints or the program will crash


## Usage
```go
package main

import (
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/janishutz/oidclogin"
)

func main() {
	r := gin.Default()

	// TODO: Better secret
	store := memstore.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("jhid", store))

	oidclogin.Configure(r, os.Getenv("APP_BASE_URL"), "/account", false)
	r.LoadHTMLGlob("public/*")

	r.GET("/account", oidclogin.EnsureLogin(false), func(ctx *gin.Context) {
		ctx.HTML(200, "main.tmpl", gin.H{})
	})

	r.Run()
}
```
This example further needs the environment variable `APP_BASE_URL` set to something like `https://app.example.org`.
Further, you should create a template file called `main.tmpl` and also copy over the template files in the `public` directory here and edit them.
