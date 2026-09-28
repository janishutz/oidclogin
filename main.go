package oidclogin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func createRandomString(n int) (string, error) {
	s := make([]byte, n)
	if _, err := rand.Read(s); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(s), nil
}

type UserFunc func(userid string, name string, email string)

var (
	config          oauth2.Config
	userFunc        UserFunc
	verifier        oidc.IDTokenVerifier
	defaultRedirect string
)

// Wraps the normal configure function, but also gives you access to change the User Function, which is called upon login.
// It is used to create or update a user.
// The check middleware may be nil, in which case a default is used. Otherwise should be a valid gin middleware, calling c.Next() if okay to proceed.
func ConfigureFull(r *gin.Engine, app_url string, default_redirect string, user_function UserFunc, stubs_on_unconfigured bool, check_middleware func(c *gin.Context)) {
	userFunc = user_function
	Configure(r, app_url, default_redirect, stubs_on_unconfigured, check_middleware)
}

// Configure and set up the login SDK
// The check middleware may be nil, in which case a default is used. Otherwise should be a valid gin middleware, calling c.Next() if okay to proceed.
func Configure(r *gin.Engine, app_url string, default_redirect string, stubs_on_unconfigured bool, check_middleware func(c *gin.Context)) {
	issuer := os.Getenv("OIDC_ISSUER")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	defaultRedirect = default_redirect

	if issuer == "" || clientID == "" || clientSecret == "" {
		if stubs_on_unconfigured {
			log.Println("[JHID] WARNING: OIDC not set up due to missing environment variables. Falling back to stubs")
			startStubs(r, check_middleware)
			return
		} else {
			log.Fatal("[JHID] One or more requried environment variables are missing. See docs for more information")
		}
	}

	provider, err := oidc.NewProvider(context.Background(), issuer)
	verifier = *provider.Verifier(&oidc.Config{ClientID: clientID})

	if err != nil {
		log.Fatal("[JHID] Provider resolution failed with error", err)
	}

	config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  app_url + "/auth/v2/verify",
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	r.GET("/auth/v2/login", loginHandler)
	r.GET("/auth/v2/verify", callbackHandler)
	if check_middleware == nil {
		r.GET("/auth/v2/check", EnsureLogin(false), check_finalizer)
	} else {
		log.Println("[JHID] Custom check middleware enabled")
		r.GET("/auth/v2/check", EnsureLogin(false), check_middleware, check_finalizer)
	}
	r.GET("/auth/v2/logout", logoutHandler)

	log.Println("[JHID] Configured successfully")
}

func check_finalizer(ctx *gin.Context) { ctx.JSON(200, gin.H{"success": "true"}) }

func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			log.Println("Error during route:", c.Errors.Last().Err)

			c.JSON(500, gin.H{
				"error": "Internal Server Error",
			})
		}
	}
}
