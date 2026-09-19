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
	codeVerifier := session.Get("jhid_oauth_code_verifier").(string)

	if c.Query("state") != state {
		log.Println("State invalid")
		// TODO: Proper pages
		c.HTML(500, "oidcerror.tmpl", gin.H{
			"error": "",
		})
		c.AbortWithStatus(500)
		return
	}

	// Token exchange
	tok, err := config.Exchange(c, c.Query("code"), oauth2.VerifierOption(codeVerifier))
	if err != nil {
		log.Println("Token exchange failed with error", err)
		c.AbortWithStatus(500)
		return
	}

	// Extract ID token
	rawIdToken, ok := tok.Extra("id_token").(string)
	if !ok {
		log.Println("Failed to get ID token", err)
		c.AbortWithStatus(500)
		return
	}
	idToken, err := verifier.Verify(c, rawIdToken)
	if err != nil {
		log.Println("Token verification failed", err)
		c.AbortWithStatus(500)
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

	session.Delete("jhid_oauth_nonce")
	session.Delete("jhid_oauth_state")
	session.Delete("jhid_oauth_code_verifier")

	session.Set("jhid_auth", true)
	session.Save()
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
				c.AbortWithStatus(401)
				return
			}
		}
	})
}
