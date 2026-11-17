package webapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// browser log in: a page with a form instead of the browser's Basic Auth prompt.
// a right user/password sets a signed cookie; API clients keep using Basic Auth.

const (
	sessionCookie = "tgspam_session"
	sessionTTL    = 30 * 24 * time.Hour
	loginMaxFails = 10
	loginFailWin  = 10 * time.Minute
)

// paths reachable without being logged in (the login page and what it loads)
var publicPaths = map[string]bool{"/login": true, "/logout": true, "/styles.css": true, "/logo.png": true, "/spinner.svg": true}

type loginLimiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(ip)) >= loginMaxFails
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fails == nil {
		l.fails = map[string][]time.Time{}
	}
	l.fails[ip] = append(l.recent(ip), time.Now())
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}

// recent drops failures older than the window; caller holds the lock
func (l *loginLimiter) recent(ip string) []time.Time {
	var res []time.Time
	for _, t := range l.fails[ip] {
		if time.Since(t) < loginFailWin {
			res = append(res, t)
		}
	}
	if len(res) == 0 {
		delete(l.fails, ip)
	} else if l.fails != nil {
		l.fails[ip] = res
	}
	return res
}

// activeAuthHash returns the bcrypt hash in use, same precedence as checkBasicAuth
func (s *Server) activeAuthHash() string {
	s.appSettingsMu.RLock()
	defer s.appSettingsMu.RUnlock()
	if s.AppSettings != nil && s.AppSettings.Server.AuthHash != "" {
		return s.AppSettings.Server.AuthHash
	}
	return s.AuthHash
}

// sessionSig signs user+expiry with a key made from the password hash,
// so changing the password logs every browser out
func (s *Server) sessionSig(user string, exp int64) string {
	key := sha256.Sum256([]byte("tg-spam-session:" + s.activeAuthHash()))
	m := hmac.New(sha256.New, key[:])
	_, _ = fmt.Fprintf(m, "%s|%d", user, exp)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) newSessionValue(user string) string {
	exp := time.Now().Add(sessionTTL).Unix()
	return fmt.Sprintf("%s.%d.%s", base64.RawURLEncoding.EncodeToString([]byte(user)), exp, s.sessionSig(user, exp))
}

func (s *Server) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return false
	}
	u, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	if string(u) != s.activeAuthUser() || s.activeAuthHash() == "" {
		return false
	}
	return hmac.Equal([]byte(parts[2]), []byte(s.sessionSig(string(u), exp)))
}

func isSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: isSecure(r), SameSite: http.SameSiteLaxMode})
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-Ip"); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// wantsPage tells a browser page load from an API call
func wantsPage(r *http.Request) bool {
	return r.Method == http.MethodGet && r.Header.Get("HX-Request") == "" &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

// safeNext keeps the after-login redirect on this site
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") ||
		strings.HasPrefix(next, "/login") || strings.HasPrefix(next, "/logout") {
		return "/"
	}
	return next
}

func (s *Server) loginPageHandler(w http.ResponseWriter, r *http.Request) {
	if s.activeAuthHash() == "" || s.validSession(r) { // no password set, or already logged in
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	s.renderLogin(w, http.StatusOK, r.URL.Query().Get("next"), "", "")
}

func (s *Server) loginSubmitHandler(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	next := r.FormValue("next")
	user := strings.TrimSpace(r.FormValue("username"))
	if s.loginLimit.blocked(ip) {
		s.renderLogin(w, http.StatusTooManyRequests, next, user, "Too many tries. Wait a few minutes and try again.")
		return
	}
	if !s.checkBasicAuth(user, r.FormValue("password")) {
		s.loginLimit.fail(ip)
		log.Printf("[WARN] failed web login for %q from %s", user, ip)
		s.renderLogin(w, http.StatusUnauthorized, next, user, "Wrong username or password.")
		return
	}
	s.loginLimit.reset(ip)
	setSessionCookie(w, r, s.newSessionValue(user), int(sessionTTL.Seconds()))
	http.Redirect(w, r, safeNext(next), http.StatusSeeOther)
}

func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	setSessionCookie(w, r, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, next, user, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	data := struct{ Next, User, Error string }{Next: safeNext(next), User: user, Error: errMsg}
	if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("[WARN] can't execute login template: %v", err)
	}
}

// loginRedirect sends a browser to the login page, an HTMX call to a full-page redirect
func loginRedirect(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("HX-Redirect", "/login")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return true
	}
	if wantsPage(r) {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return true
	}
	return false
}
