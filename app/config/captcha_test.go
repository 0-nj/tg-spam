package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCaptchaSettings_ValidateExtra(t *testing.T) {
	c := CaptchaSettings{Enabled: true, Question: "q", Options: []string{"a", "b"}, Answer: 1, Timeout: time.Minute, FailAction: "ban",
		Extra: []CaptchaQuestion{{Question: "q2", Options: []string{"x", "y"}, Answer: 2}}}
	require.NoError(t, c.validate())
	c.Extra = append(c.Extra, CaptchaQuestion{Question: "q3", Options: []string{"x", "y"}, Answer: 5})
	err := c.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "question 3")
	assert.Len(t, c.AllQuestions(), 3)
}
