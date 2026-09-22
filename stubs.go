package oidclogin

import (
	"log"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func startStubs(r *gin.Engine) {
	r.GET("/auth/v2/login", stubsHandler)
	r.GET("/auth/v2/verify", stubsHandler)
	r.GET("/auth/v2/check", EnsureLogin(false), func(ctx *gin.Context) { ctx.JSON(200, gin.H{"success": "true"}) })
	r.GET("/auth/v2/logout", logoutHandler)
}

func stubsHandler(c *gin.Context) {
	redir := c.Query("returnTo")
	session := sessions.Default(c)
	if userFunc != nil {
		userFunc("stubs", "Stubs User", "example@example.com")
	} else {
		log.Println("[JHID] WARNING: No user function defined")
	}
	session.Set("jhid_auth", true)
	session.Set("jhid_uid", "stubs")
	session.Save()
	if redir != "" {
		log.Println("[JHID] Redirecting to ", redir)
		c.Redirect(307, redir)
	} else {
		log.Println("[JHID] Redirecting to ", defaultRedirect, " (default redirect)")
		c.Redirect(307, defaultRedirect)
	}
}
