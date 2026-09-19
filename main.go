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

var (
	config          oauth2.Config
	userFunc        func(userid string, name string, email string)
	verifier        oidc.IDTokenVerifier
	defaultRedirect string
)

// Configure and set up the login SDK.
func Configure(r *gin.Engine, app_url string, default_redirect string, stubs_on_unconfigured bool) {
	issuer := os.Getenv("OIDC_ISSUER")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")

	if issuer == "" || clientID == "" || clientSecret == "" {
		if stubs_on_unconfigured {
			log.Println("[JHID] WARNING: OIDC not set up due to missing environment variables. Falling back to stubs")
			startStubs(r)
			return
		} else {
			log.Fatal("[JHID] One or more requried environment variables are missing. See docs for more information")
		}
	}

	provider, err := oidc.NewProvider(context.Background(), issuer)
	verifier = *provider.Verifier(&oidc.Config{ClientID: clientID})
	defaultRedirect = default_redirect

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

	log.Println("[JHID] Configured successfully")
}

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
