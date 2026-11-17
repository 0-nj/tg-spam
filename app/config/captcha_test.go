package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCaptchaSettings_Validate(t *testing.T) {
	good := CaptchaSettings{Enabled: true, Question: "q", Options: []string{"a", "b"}, Answer: 2,
		Timeout: 3 * time.Minute, FailAction: "kick"}
	tests := []struct {
		name    string
		mod     func(c *CaptchaSettings)
		wantErr string
	}{
		{name: "valid", mod: func(*CaptchaSettings) {}},
		{name: "disabled skips checks", mod: func(c *CaptchaSettings) { *c = CaptchaSettings{} }},
		{name: "no question", mod: func(c *CaptchaSettings) { c.Question = " " }, wantErr: "question"},
		{name: "one option", mod: func(c *CaptchaSettings) { c.Options = []string{"a"} }, wantErr: "2 to 8"},
		{name: "empty option", mod: func(c *CaptchaSettings) { c.Options = []string{"a", " "} }, wantErr: "empty"},
		{name: "answer out of range", mod: func(c *CaptchaSettings) { c.Answer = 3 }, wantErr: "answer"},
		{name: "short timeout", mod: func(c *CaptchaSettings) { c.Timeout = 10 * time.Second }, wantErr: "timeout"},
		{name: "bad action", mod: func(c *CaptchaSettings) { c.FailAction = "x" }, wantErr: "fail-action"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.mod(&c)
			s := New()
			s.Captcha = c
			err := s.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}
