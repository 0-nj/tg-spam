package events

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tbapi "github.com/OvyFlash/telegram-bot-api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/tg-spam/app/events/mocks"
)

const testGroupID = int64(-100123)

func testCaptchaConfig() CaptchaConfig {
	return CaptchaConfig{Enabled: true, Question: "What is 2+2?", Options: []string{"3", "4", "5"}, Answer: 2,
		Timeout: time.Minute, FailAction: CaptchaFailKick, Intro: "Hi {name}, {seconds}s", PassMsg: "ok",
		FailMsg: "bad", NotYours: "not yours"}
}

// captchaAPI returns a mock where sends to the chats in noDM fail, like Telegram does for users who never started the bot
func captchaAPI(noDM ...int64) *mocks.TbAPIMock {
	var msgID int
	return &mocks.TbAPIMock{
		SendFunc: func(c tbapi.Chattable) (tbapi.Message, error) {
			if m, ok := c.(tbapi.MessageConfig); ok {
				for _, id := range noDM {
					if m.ChatID == id {
						return tbapi.Message{}, errors.New("Forbidden: bot can't initiate conversation with a user")
					}
				}
			}
			msgID++
			return tbapi.Message{MessageID: msgID}, nil
		},
		RequestFunc: func(c tbapi.Chattable) (*tbapi.APIResponse, error) { return &tbapi.APIResponse{Ok: true}, nil },
	}
}

func newTestCaptcha(api *mocks.TbAPIMock, cfg CaptchaConfig) *captcha {
	c := newCaptcha(api, cfg)
	c.setChat(testGroupID, "Group")
	return c
}

// buttonData returns the callback data of the button with the given text in the last question sent
func buttonData(t *testing.T, api *mocks.TbAPIMock, text string) string {
	t.Helper()
	calls := api.SendCalls()
	require.NotEmpty(t, calls)
	msg, ok := calls[len(calls)-1].C.(tbapi.MessageConfig)
	require.True(t, ok)
	kb, ok := msg.ReplyMarkup.(tbapi.InlineKeyboardMarkup)
	require.True(t, ok)
	for _, row := range kb.InlineKeyboard {
		if row[0].Text == text {
			return *row[0].CallbackData
		}
	}
	t.Fatalf("no button %q", text)
	return ""
}

func requestsOf[T any](api *mocks.TbAPIMock) []T {
	var res []T
	for _, c := range api.RequestCalls() {
		if v, ok := c.C.(T); ok {
			res = append(res, v)
		}
	}
	return res
}

func TestCaptcha_NewMemberInDM(t *testing.T) {
	api := captchaAPI()
	c := newTestCaptcha(api, testCaptchaConfig())
	c.OnNewMember(&tbapi.User{ID: 42, FirstName: "Ann"})

	mutes := requestsOf[tbapi.RestrictChatMemberConfig](api)
	require.Len(t, mutes, 1)
	assert.False(t, mutes[0].Permissions.CanSendMessages)
	assert.NotZero(t, mutes[0].UntilDate, "mute ends by itself")

	sent := api.SendCalls()[0].C.(tbapi.MessageConfig)
	assert.Equal(t, int64(42), sent.ChatID, "asked in DM")
	assert.Contains(t, sent.Text, `<a href="tg://user?id=42">Ann</a>`)
	assert.Contains(t, sent.Text, "60s")
	assert.Contains(t, sent.Text, "What is 2+2?")

	data := buttonData(t, api, "4")
	require.NoError(t, c.OnCallback(&tbapi.CallbackQuery{ID: "1", From: &tbapi.User{ID: 42}, Data: data}))

	mutes = requestsOf[tbapi.RestrictChatMemberConfig](api)
	require.Len(t, mutes, 2)
	assert.True(t, mutes[1].Permissions.CanSendMessages, "mute lifted")
	assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
	edit, ok := api.SendCalls()[1].C.(tbapi.EditMessageTextConfig)
	require.True(t, ok, "DM question replaced by the result")
	assert.Equal(t, "ok", edit.Text)
	assert.Empty(t, c.pending)
}

func TestCaptcha_GroupFallbackWrongAnswer(t *testing.T) {
	api := captchaAPI(42)
	c := newTestCaptcha(api, testCaptchaConfig())
	c.OnNewMember(&tbapi.User{ID: 42, FirstName: "Ann"})

	calls := api.SendCalls()
	require.Len(t, calls, 2)
	assert.Equal(t, testGroupID, calls[1].C.(tbapi.MessageConfig).ChatID, "asked in the group")

	data := buttonData(t, api, "3")
	// another member can't answer
	require.NoError(t, c.OnCallback(&tbapi.CallbackQuery{ID: "x", From: &tbapi.User{ID: 7}, Data: data}))
	cbs := requestsOf[tbapi.CallbackConfig](api)
	require.Len(t, cbs, 1)
	assert.True(t, cbs[0].ShowAlert)
	assert.Equal(t, "not yours", cbs[0].Text)
	assert.Len(t, c.pending, 1)

	require.NoError(t, c.OnCallback(&tbapi.CallbackQuery{ID: "y", From: &tbapi.User{ID: 42}, Data: data}))
	assert.Len(t, requestsOf[tbapi.DeleteMessageConfig](api), 1, "group question deleted")
	assert.Len(t, requestsOf[tbapi.BanChatMemberConfig](api), 1, "kicked")
	unban := requestsOf[tbapi.UnbanChatMemberConfig](api)
	require.Len(t, unban, 1, "kick lets them join again")
	assert.True(t, unban[0].OnlyIfBanned)
	assert.Empty(t, c.pending)
}

func TestCaptcha_Timeout(t *testing.T) {
	for _, tc := range []struct {
		action              string
		bans, unbans, mutes int
	}{
		{action: CaptchaFailKick, bans: 1, unbans: 1, mutes: 1},
		{action: CaptchaFailBan, bans: 1, mutes: 1},
		{action: CaptchaFailMute, mutes: 2},
	} {
		t.Run(tc.action, func(t *testing.T) {
			api := captchaAPI(42)
			cfg := testCaptchaConfig()
			cfg.FailAction = tc.action
			c := newTestCaptcha(api, cfg)
			c.OnNewMember(&tbapi.User{ID: 42, FirstName: "Ann"})
			ch := c.pending[42]
			require.NotNil(t, ch)
			ch.timer.Stop()
			c.onTimeout(42, ch.seq)
			assert.Len(t, requestsOf[tbapi.DeleteMessageConfig](api), 1)
			assert.Len(t, requestsOf[tbapi.BanChatMemberConfig](api), tc.bans)
			assert.Len(t, requestsOf[tbapi.UnbanChatMemberConfig](api), tc.unbans)
			mutes := requestsOf[tbapi.RestrictChatMemberConfig](api)
			assert.Len(t, mutes, tc.mutes)
			if tc.action == CaptchaFailMute {
				assert.Zero(t, mutes[1].UntilDate, "muted for good")
			}
			assert.Empty(t, c.pending)
		})
	}
}

func TestCaptcha_JoinRequest(t *testing.T) {
	t.Run("correct answer approves and skips the group question", func(t *testing.T) {
		api := captchaAPI()
		c := newTestCaptcha(api, testCaptchaConfig())
		req := &tbapi.ChatJoinRequest{Chat: tbapi.Chat{ID: testGroupID}, From: tbapi.User{ID: 42, FirstName: "Ann"}, UserChatID: 42}
		c.OnJoinRequest(req)
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api), "not a member yet")
		require.NoError(t, c.OnCallback(&tbapi.CallbackQuery{ID: "1", From: &tbapi.User{ID: 42}, Data: buttonData(t, api, "4")}))
		assert.Len(t, requestsOf[tbapi.ApproveChatJoinRequestConfig](api), 1)

		sends := len(api.SendCalls())
		c.OnNewMember(&tbapi.User{ID: 42, FirstName: "Ann"})
		assert.Len(t, api.SendCalls(), sends, "no second question")
		assert.Empty(t, requestsOf[tbapi.RestrictChatMemberConfig](api))
	})

	t.Run("wrong answer declines", func(t *testing.T) {
		api := captchaAPI()
		c := newTestCaptcha(api, testCaptchaConfig())
		c.OnJoinRequest(&tbapi.ChatJoinRequest{Chat: tbapi.Chat{ID: testGroupID}, From: tbapi.User{ID: 42}, UserChatID: 42})
		require.NoError(t, c.OnCallback(&tbapi.CallbackQuery{ID: "1", From: &tbapi.User{ID: 42}, Data: buttonData(t, api, "5")}))
		assert.Len(t, requestsOf[tbapi.DeclineChatJoinRequest](api), 1)
		assert.Empty(t, requestsOf[tbapi.ApproveChatJoinRequestConfig](api))
	})

	t.Run("no DM approves for a group question", func(t *testing.T) {
		api := captchaAPI(42)
		c := newTestCaptcha(api, testCaptchaConfig())
		c.OnJoinRequest(&tbapi.ChatJoinRequest{Chat: tbapi.Chat{ID: testGroupID}, From: tbapi.User{ID: 42}, UserChatID: 42})
		assert.Len(t, requestsOf[tbapi.ApproveChatJoinRequestConfig](api), 1)
		assert.Empty(t, c.pending)
	})

	t.Run("other chat ignored", func(t *testing.T) {
		api := captchaAPI()
		c := newTestCaptcha(api, testCaptchaConfig())
		c.OnJoinRequest(&tbapi.ChatJoinRequest{Chat: tbapi.Chat{ID: -5}, From: tbapi.User{ID: 42}, UserChatID: 42})
		assert.Empty(t, api.SendCalls())
		assert.Empty(t, api.RequestCalls())
	})
}

func TestCaptcha_Skips(t *testing.T) {
	api := captchaAPI()
	c := newTestCaptcha(api, testCaptchaConfig())
	c.isSuper = func(name string, _ int64) bool { return name == "admin" }
	c.isApproved = func(id int64) bool { return id == 5 }
	c.OnNewMember(&tbapi.User{ID: 1, UserName: "admin"})
	c.OnNewMember(&tbapi.User{ID: 5})
	c.OnNewMember(&tbapi.User{ID: 6, IsBot: true})
	assert.Empty(t, api.SendCalls())
	assert.Empty(t, api.RequestCalls())

	c.SetConfig(CaptchaConfig{})
	c.OnNewMember(&tbapi.User{ID: 9})
	assert.Empty(t, api.SendCalls(), "disabled")
}

func TestCaptcha_ShuffleKeepsAnswer(t *testing.T) {
	cfg := testCaptchaConfig()
	cfg.Shuffle = true
	for i := range 20 {
		api := captchaAPI()
		c := newTestCaptcha(api, cfg)
		id := int64(100 + i)
		c.OnNewMember(&tbapi.User{ID: id})
		require.NoError(t, c.OnCallback(&tbapi.CallbackQuery{ID: "1", From: &tbapi.User{ID: id}, Data: buttonData(t, api, "4")}))
		assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
	}
}

func TestCaptcha_StaleAndBadCallbacks(t *testing.T) {
	api := captchaAPI()
	c := newTestCaptcha(api, testCaptchaConfig())
	c.OnNewMember(&tbapi.User{ID: 42})
	data := buttonData(t, api, "4")
	parts := strings.Split(data, ":")
	stale := fmt.Sprintf("Q:%s:%d:%s", parts[1], 999, parts[3])
	require.NoError(t, c.OnCallback(&tbapi.CallbackQuery{ID: "1", From: &tbapi.User{ID: 42}, Data: stale}))
	assert.Len(t, c.pending, 1, "stale button ignored")
	require.Error(t, c.OnCallback(&tbapi.CallbackQuery{ID: "1", From: &tbapi.User{ID: 42}, Data: "Q:bad"}))

	c.OnLeft(42)
	assert.Empty(t, c.pending)
	assert.Len(t, requestsOf[tbapi.DeleteMessageConfig](api), 1)
}

func TestCaptcha_PassMute(t *testing.T) {
	api := captchaAPI(42)
	cfg := testCaptchaConfig()
	cfg.PassMute = 15 * time.Minute
	c := newTestCaptcha(api, cfg)
	c.OnNewMember(&tbapi.User{ID: 42, FirstName: "Ann"})
	require.NoError(t, c.OnCallback(&tbapi.CallbackQuery{ID: "1", From: &tbapi.User{ID: 42}, Data: buttonData(t, api, "4")}))

	mutes := requestsOf[tbapi.RestrictChatMemberConfig](api)
	require.Len(t, mutes, 2)
	assert.False(t, mutes[1].Permissions.CanSendMessages, "still muted")
	left := time.Until(time.Unix(mutes[1].UntilDate, 0))
	assert.InDelta(t, (15 * time.Minute).Seconds(), left.Seconds(), 5, "Telegram lifts it after 15 minutes")
	assert.Empty(t, requestsOf[tbapi.BanChatMemberConfig](api))
	assert.Empty(t, c.pending)
}
