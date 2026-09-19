package oidclogin

import "github.com/gin-gonic/gin"

func startStubs(r *gin.Engine) {
	r.GET("/auth/v2/login", func(ctx *gin.Context) {
		redir := ctx.Query("returnTo")
		if redir != "" {
			ctx.Redirect(307, redir)
		} else {
			ctx.Redirect(307, defaultRedirect)
		}
	})
	r.GET("/auth/v2/verify", func(ctx *gin.Context) {
		redir := ctx.Query("returnTo")
		if redir != "" {
			ctx.Redirect(307, redir)
		} else {
			ctx.Redirect(307, defaultRedirect)
		}
	})
}
