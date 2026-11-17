package webapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func newLoginTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)
	s := NewServer(Config{AuthHash: string(hash)})
	inner := http.NewServeMux()
	inner.HandleFunc("GET /login", s.loginPageHandler)
	inner.HandleFunc("POST /login", s.loginSubmitHandler)
	inner.HandleFunc("GET /logout", s.logoutHandler)
	inner.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("inside")) })
	return s, s.basicAuthMiddleware(inner)
}

func login(t *testing.T, h http.Handler, user, pass string) *http.Response {
	t.Helper()
	form := url.Values{"username": {user}, "password": {pass}, "next": {"/list_settings"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Result()
}

func TestLogin_BrowserFlow(t *testing.T) {
	_, h := newLoginTestServer(t)

	// a browser without a session goes to the log-in page, no Basic Auth prompt
	req := httptest.NewRequest("GET", "/list_settings", http.NoBody)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login?next=%2Flist_settings", w.Header().Get("Location"))
	assert.Empty(t, w.Header().Get("WWW-Authenticate"))

	// the page renders
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/login?next=/list_settings", http.NoBody))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `name="password"`)

	resp := login(t, h, "tg-spam", "bad")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Cookies())

	resp = login(t, h, "tg-spam", "secret")
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/list_settings", resp.Header.Get("Location"))
	require.Len(t, resp.Cookies(), 1)
	cookie := resp.Cookies()[0]
	assert.True(t, cookie.HttpOnly)

	req = httptest.NewRequest("GET", "/list_settings", http.NoBody)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, "inside", w.Body.String())

	// tampered cookie is refused
	bad := *cookie
	bad.Value = cookie.Value[:len(cookie.Value)-2] + "xx"
	req = httptest.NewRequest("POST", "/config", http.NoBody)
	req.AddCookie(&bad)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// log out clears the cookie
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/logout", http.NoBody))
	assert.Equal(t, "/login", w.Header().Get("Location"))
	require.Len(t, w.Result().Cookies(), 1)
	assert.Negative(t, w.Result().Cookies()[0].MaxAge)
}

func TestLogin_APIAndHTMX(t *testing.T) {
	_, h := newLoginTestServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/check", http.NoBody))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NotEmpty(t, w.Header().Get("WWW-Authenticate"), "API clients keep Basic Auth")

	req := httptest.NewRequest("GET", "/check", http.NoBody)
	req.SetBasicAuth("tg-spam", "secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, "inside", w.Body.String())

	req = httptest.NewRequest("PUT", "/config", http.NoBody)
	req.Header.Set("HX-Request", "true")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, "/login", w.Header().Get("HX-Redirect"))
	assert.Empty(t, w.Header().Get("WWW-Authenticate"), "no browser prompt for htmx calls")
}

func TestLogin_LimitsAndRotation(t *testing.T) {
	s, h := newLoginTestServer(t)
	for range loginMaxFails {
		login(t, h, "tg-spam", "bad")
	}
	assert.Equal(t, http.StatusTooManyRequests, login(t, h, "tg-spam", "secret").StatusCode)
	s.loginLimit.reset("10.0.0.1")

	cookie := login(t, h, "tg-spam", "secret").Cookies()[0]
	newHash, err := bcrypt.GenerateFromPassword([]byte("other"), bcrypt.MinCost)
	require.NoError(t, err)
	s.AuthHash = string(newHash) // password changed: old sessions stop working
	req := httptest.NewRequest("GET", "/x", http.NoBody)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"": "/", "/list_settings": "/list_settings", "//evil.com": "/",
		"https://evil.com": "/", "/\\evil.com": "/", "/logout": "/", "/manage_users?x=1": "/manage_users?x=1"} {
		assert.Equal(t, want, safeNext(in), in)
	}
}
