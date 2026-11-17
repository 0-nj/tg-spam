package webapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/tg-spam/app/config"
)

func TestUpdateCaptchaFromForm(t *testing.T) {
	newReq := func(v url.Values) *http.Request {
		r, err := http.NewRequest(http.MethodPost, "/config", strings.NewReader(v.Encode()))
		require.NoError(t, err)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		require.NoError(t, r.ParseForm())
		return r
	}

	t.Run("form without the captcha section keeps settings", func(t *testing.T) {
		s := &config.Settings{Captcha: config.CaptchaSettings{Enabled: true, Question: "q"}}
		updateCaptchaFromForm(s, newReq(url.Values{"other": {"1"}}))
		assert.True(t, s.Captcha.Enabled)
		assert.Equal(t, "q", s.Captcha.Question)
	})

	t.Run("captcha section applied", func(t *testing.T) {
		s := &config.Settings{Captcha: config.CaptchaSettings{Enabled: true, Options: []string{"old"}}}
		updateCaptchaFromForm(s, newReq(url.Values{
			"captchaForm": {"1"}, "captchaShuffle": {"on"}, "captchaQuestion": {" What? "},
			"captchaOptions": {"a\r\n\r\n b \nc"}, "captchaAnswer": {"2"}, "captchaTimeout": {"90s"},
			"captchaFailAction": {"ban"}, "captchaIntro": {"hi {name}"}, "captchaPassMsg": {"ok"},
			"captchaFailMsg": {"no"}, "captchaNotYours": {"nope"},
		}))
		assert.Equal(t, config.CaptchaSettings{Enabled: false, Shuffle: true, Question: "What?",
			Options: []string{"a", "b", "c"}, Answer: 2, Timeout: 90 * time.Second, FailAction: "ban",
			Intro: "hi {name}", PassMsg: "ok", FailMsg: "no", NotYours: "nope"}, s.Captcha)
	})
}

func TestRestartHandler(t *testing.T) {
	done := make(chan struct{})
	s := &Server{Config: Config{Restart: func() { close(done) }}}
	w := httptest.NewRecorder()
	s.restartHandler(w, httptest.NewRequest(http.MethodPost, "/config/restart", http.NoBody))
	assert.Contains(t, w.Body.String(), "Restarting")
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("restart not called")
	}
}
