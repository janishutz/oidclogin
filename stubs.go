package oidclogin

import (
	"log"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func startStubs(r *gin.Engine, check_middleware func(c *gin.Context)) {
	r.GET("/auth/v2/login", stubsHandler)
	r.GET("/auth/v2/verify", stubsHandler)
	if check_middleware == nil {
		r.GET("/auth/v2/check", EnsureLogin(false), check_finalizer)
	} else {
		log.Println("[JHID] Custom check middleware enabled")
		r.GET("/auth/v2/check", EnsureLogin(false), check_middleware, check_finalizer)
	}
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
