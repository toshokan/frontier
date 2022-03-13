package server

import (
	"github.com/toshokan/frontier/internal/config"
	"github.com/toshokan/frontier/internal/security"
	"github.com/toshokan/frontier/internal/oauth"
	"net/http"
	"time"
)

const (
	cookieName = "Frontier-Session"
	sessionCookieLabel = "session_cookie"
	callbackPath = "/frontier/oauth/callback"
)

type SessionCookie struct {
	Expires int64  `json:"expires"`
	Subject string `json:"sub"`
}

func MakeSessionCookie(user string) SessionCookie {
	expiry := time.Now().Add(60 * time.Minute).Unix()
	return SessionCookie { expiry, user }
}

func GetSessionCookie(cfg *config.Config, r *http.Request) (*SessionCookie, error) {
	var sess SessionCookie
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		// Cookie was not found
		return nil, nil
	}
	if err = security.DecryptAsJson(cfg, cookie.Value, &sess, sessionCookieLabel); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (sess *SessionCookie) IsValid() bool {
	exp := time.Unix(sess.Expires, 0)
	return time.Now().Before(exp)
}

func authHandler(cfg *config.Config) http.HandlerFunc {
	handle := oauth.NewAuthHandle(cfg)
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := GetSessionCookie(cfg, r)
		if err == nil && cookie == nil {
			originalUrl := r.Header.Get("Frontier-Original-Url")
			authUrl, err := handle.GetAuthorizationRequestUrl(originalUrl, callbackPath)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			// There was no cookie sent, need to create a session
			w.Header().Set("Frontier-Location", authUrl.String())
			w.Header().Set("WWW-Authenticate", "Frontier-Redirect")
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			// Either there was cookie or there was an error
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			//  There was no error, so cookie is non-nil

			// Is it still valid?
			if !cookie.IsValid() {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Everything is fine
			w.WriteHeader(http.StatusOK)
			return
		}
	})
}

func authCallback(cfg *config.Config) http.HandlerFunc {
	authHandler := oauth.NewAuthHandle(cfg)
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		token, state, err := authHandler.GetToken(query.Get("code"), query.Get("state"), callbackPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return;
		}
		info, err := authHandler.GetUserInfo(token.AccessToken)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return;
		}
		sess := MakeSessionCookie(info.Subject)
		cookieValue, err := security.EncryptAsJson(cfg, &sess, sessionCookieLabel)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		
		var cookie http.Cookie
		cookie.Name = cookieName
		cookie.Value = cookieValue
		http.SetCookie(w, &cookie)

		w.Header().Set("Location", state.OriginalUrl)
		w.WriteHeader(http.StatusSeeOther)
	})
}

func Mount(cfg *config.Config) {
	http.Handle("/frontier/checkAuth", authHandler(cfg))
	http.Handle(callbackPath, authCallback(cfg))
	http.ListenAndServe(":8000", nil)
}
