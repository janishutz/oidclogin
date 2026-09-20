package oidclogin

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func startStubs(r *gin.Engine) {
	r.GET("/auth/v2/login", stubsHandler)
	r.GET("/auth/v2/verify", stubsHandler)
}

func stubsHandler(c *gin.Context) {
	redir := c.Query("returnTo")
	session := sessions.Default(c)
	userFunc("stubs", "Stubs User", "example@example.com")
	session.Set("jhid_auth", true)
	session.Set("jhid_uid", "stubs")
	session.Save()
	if redir != "" {
		c.Redirect(307, redir)
	} else {
		c.Redirect(307, defaultRedirect)
	}
}
