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
	config   oauth2.Config
	userFunc func(userid string, name string, email string)
	verifier oidc.IDTokenVerifier
)

func Configure(r *gin.Engine, app_url string, scopes []string) {
	r.GET("/auth/v2/login", LoginHandler)
	r.GET("/auth/v2/verify", CallbackHandler)

	provider, err := oidc.NewProvider(context.Background(), os.Getenv("OIDC_ISSUER"))
	clientID := os.Getenv("OIDC_CLIENT_ID")
	verifier = *provider.Verifier(&oidc.Config{ClientID: clientID})
	if err != nil {
		log.Fatal("Provider resolution failed with error", err)
	}

	config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  app_url + "/auth/v2/verify",
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}
