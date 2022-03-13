package server

import (
	"github.com/toshokan/frontier/internal/config"
	"github.com/toshokan/frontier/internal/security"
	"github.com/toshokan/frontier/internal/oauth"
	"net/http"
	"time"
	"log"
	"crypto/rand"
	"encoding/base64"
	"context"
)

const (
	cookieName = "Frontier-Session"
	sessionCookieLabel = "session_cookie"
	callbackPath = "/frontier/oauth/callback"
	RequestId = "RequestId"
)

func requestId(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		bs := make([]byte, 18)
		rand.Read(bs)
		id := base64.URLEncoding.EncodeToString(bs)
		ctx := context.WithValue(req.Context(), RequestId, id)

		log.Printf("%s Processing request", id)
		next.ServeHTTP(w, req.WithContext(ctx))
		log.Printf("%s Done processing request", id)
	})
}


type SessionCookie struct {
	Expires int64  `json:"expires"`
	Subject string `json:"sub"`
}

func MakeSessionCookie(user string) SessionCookie {
	log.Printf("Building session cookie for user = %s", user)
	expiry := time.Now().Add(60 * time.Minute).Unix()
	return SessionCookie { expiry, user }
}

func GetSessionCookie(cfg *config.Config, r *http.Request) (*SessionCookie, error) {
	var rid = r.Context().Value(RequestId)
	
	var sess SessionCookie
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		log.Printf("%s No session cookie found", rid)
		// Cookie was not found
		return nil, nil
	}
	if err = security.DecryptAsJson(cfg, cookie.Value, &sess, sessionCookieLabel); err != nil {
		log.Printf("%s Error decrypting session cookie. err = %s", rid, err)
		return nil, err
	}
	return &sess, nil
}

func (sess *SessionCookie) IsValid() bool {
	exp := time.Unix(sess.Expires, 0)
	return time.Now().Before(exp)
}

func performAuthenticationRedirect(authHandle *oauth.AuthHandle, w http.ResponseWriter, r *http.Request) {
	var rid = r.Context().Value(RequestId)
	
	originalUrl := r.Header.Get("Frontier-Original-Url")
	authUrl, err := authHandle.GetAuthorizationRequestUrl(originalUrl, callbackPath)
	if err != nil {
		log.Printf("%s Failed to build AuthorizationRequest. err = %s", rid, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// There was no cookie sent, need to create a session
	w.Header().Set("Frontier-Location", authUrl.String())
	w.Header().Set("WWW-Authenticate", "Frontier-Redirect")
	w.WriteHeader(http.StatusUnauthorized)
	return
}

func authHandler(cfg *config.Config) http.HandlerFunc {
	handle := oauth.NewAuthHandle(cfg)
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rid = r.Context().Value(RequestId)
		
		cookie, err := GetSessionCookie(cfg, r)
		if err == nil && cookie == nil {
			performAuthenticationRedirect(handle, w, r);
			return
		} else {
			// Either there was cookie or there was an error
			if err != nil {
				log.Printf("%s Error with session cookie. err = %s", rid, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			//  There was no error, so cookie is non-nil

			// Is it still valid?
			if !cookie.IsValid() {
				log.Printf("%s Session no longer valid", rid)
				performAuthenticationRedirect(handle, w, r);
				return
			}

			// Everything is fine
			log.Printf("%s Authentication OK", rid)
			w.Header().Set("Frontier-Subject", cookie.Subject)
			w.WriteHeader(http.StatusOK)
			return
		}
	})
}

func authCallback(cfg *config.Config) http.HandlerFunc {
	authHandler := oauth.NewAuthHandle(cfg)
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rid = r.Context().Value(RequestId)
		
		query := r.URL.Query()
		token, state, err := authHandler.GetToken(query.Get("code"), query.Get("state"), callbackPath)
		if err != nil {
			log.Printf("%s Failed to get access_token. err = %s", rid, err)
			w.WriteHeader(http.StatusInternalServerError)
			return;
		}
		info, err := authHandler.GetUserInfo(token.AccessToken)
		if err != nil {
			log.Printf("%s Failed to get UserInfo", rid, err)
			w.WriteHeader(http.StatusInternalServerError)
			return;
		}
		sess := MakeSessionCookie(info.Subject)
		cookieValue, err := security.EncryptAsJson(cfg, &sess, sessionCookieLabel)
		if err != nil {
			log.Printf("%s Failed to encrypt new session cookie", rid, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		
		var cookie http.Cookie
		cookie.Name = cookieName
		cookie.Value = cookieValue
		http.SetCookie(w, &cookie)

		log.Printf("%s Redirecting to original URL = %s Subject = %s", rid, state.OriginalUrl, info.Subject)
		w.Header().Set("Location", state.OriginalUrl)
		w.WriteHeader(http.StatusSeeOther)
	})
}

func Mount(cfg *config.Config) {
	http.Handle("/frontier/checkAuth", requestId(authHandler(cfg)))
	http.Handle(callbackPath, requestId(authCallback(cfg)))
	http.ListenAndServe(":8000", nil)
}
