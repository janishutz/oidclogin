package oidclogin

import (
	"crypto/rand"
	"log"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func LoginHandler(c *gin.Context) {
	// Set up user session
	state := rand.Text()
	nonce := rand.Text()
	codeVerifier := oauth2.GenerateVerifier()

	session := sessions.Default(c)
	if c.Query("returnTo") != "" {
		session.Set("redirect", c.Query("returnTo"))
	}
	session.Set("jhid_oauth_state", state)
	session.Set("jhid_oauth_nonce", nonce)
	session.Set("jhid_oauth_code_verifier", codeVerifier)
	session.Save()
	c.Redirect(301, config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(codeVerifier)))
}

func CallbackHandler(c *gin.Context) {
	session := sessions.Default(c)
	state := session.Get("jhid_oauth_state")
	nonce := session.Get("jhid_oauth_nonce")
	codeVerifier := session.Get("jhid_oauth_code_verifier")

	if c.Query("state") != state || codeVerifier == nil {
		log.Println("State invalid or verifier was not stored")
		// TODO: Proper pages
		c.HTML(500, "oidcerror.tmpl", gin.H{
			"error": "ERR_INVALID_STATE",
		})
		c.Abort()
		return
	}

	// Token exchange
	tok, err := config.Exchange(c, c.Query("code"), oauth2.VerifierOption(codeVerifier.(string)))
	if err != nil {
		log.Println("Token exchange failed with error", err)
		c.HTML(500, "oidcerror.tmpl", gin.H{
			"error": "ERR_AUTH",
		})
		c.Abort()
		return
	}

	// Extract ID token
	rawIdToken, ok := tok.Extra("id_token").(string)
	if !ok {
		log.Println("Failed to get ID token", err)
		c.HTML(500, "oidcerror.tmpl", gin.H{
			"error": "ERR_AUTH",
		})
		c.Abort()
		return
	}
	idToken, err := verifier.Verify(c, rawIdToken)
	if err != nil {
		log.Println("Token verification failed", err)
		c.HTML(500, "oidcerror.tmpl", gin.H{
			"error": "ERR_AUTH",
		})
		c.Abort()
		return
	}

	// Get claims
	var claims struct {
		Uid   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Println("Token claims generation failed", err)
		c.AbortWithStatus(500)
		return
	}

	// Verify NONCE
	if nonce != claims.Nonce {
		log.Println("Token verificcation failed", err)
		c.AbortWithStatus(500)
		return
	}

	if userFunc != nil {
		userFunc(claims.Uid, claims.Name, claims.Email)
	}

	// Clear session data of oauth related state
	session.Delete("jhid_oauth_nonce")
	session.Delete("jhid_oauth_state")
	session.Delete("jhid_oauth_code_verifier")
	redir := session.Get("redirect")
	session.Delete("redirect")

	session.Set("jhid_auth", true)
	session.Save()

	if redir != nil {
		c.Redirect(307, redir.(string))
	} else {
		c.Redirect(307, defaultRedirect)
	}
}

func EnsureLogin(redirectFail bool) func(c *gin.Context) {
	return (func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("jhid_auth") == true {
			c.Next()
		} else {
			if redirectFail {
				c.Redirect(307, "/auth/v2/login")
				c.Abort()
				return
			} else {
				c.HTML(401, "autherror.tmpl", gin.H{
					"error": "ERR_AUTH",
				})
				c.Abort()
				return
			}
		}
	})
}
