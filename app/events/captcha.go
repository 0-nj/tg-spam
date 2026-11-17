package events

import (
	"fmt"
	"html"
	"log"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	tbapi "github.com/OvyFlash/telegram-bot-api"
)

// captcha fail actions
const (
	CaptchaFailKick = "kick" // remove the member, they may join again
	CaptchaFailBan  = "ban"  // remove the member for good
	CaptchaFailMute = "mute" // keep the member in the group without the right to write
)

// captchaCallbackPrefix marks inline buttons of the captcha question
const captchaCallbackPrefix = "Q:"

// passedTTL is how long a member who answered in DM before joining is let in without a second question
const passedTTL = 10 * time.Minute

// CaptchaConfig defines the question asked to new members of the primary group
type CaptchaConfig struct {
	Enabled    bool          // ask new members the question
	Question   string        // question text
	Options    []string      // answer buttons
	Answer     int           // 1-based number of the correct option
	Timeout    time.Duration // time to answer
	FailAction string        // kick, ban or mute on a wrong answer or no answer
	Shuffle    bool          // show the options in random order
	Intro      string        // text above the question, supports {name}, {group}, {seconds} and {minutes}
	PassMsg    string        // text shown after a correct answer
	FailMsg    string        // text shown after a wrong answer or timeout
	NotYours   string        // popup for members pressing a button of someone else's question
}

// Ready tells if the config can be used to ask the question
func (c CaptchaConfig) Ready() bool {
	return c.Enabled && strings.TrimSpace(c.Question) != "" && len(c.Options) >= 2 && c.Answer >= 1 && c.Answer <= len(c.Options)
}

// captchaChallenge is a question waiting for one member's answer
type captchaChallenge struct {
	userID      int64
	name        string
	seq         int64
	msgChatID   int64 // chat holding the question, the group or the DM
	msgID       int
	viaDM       bool
	joinRequest bool // asked for a join request, not yet a member
	correct     int  // 0-based index of the correct option in the config order
	failAction  string
	failMsg     string
	passMsg     string
	timer       *time.Timer
}

// captcha asks new members a question with inline buttons, in DM when the bot can write there,
// otherwise in the group. members are muted until they answer.
type captcha struct {
	tbAPI      TbAPI
	isApproved func(userID int64) bool
	isSuper    func(userName string, userID int64) bool
	dry        bool

	mu        sync.Mutex
	cfg       CaptchaConfig
	chatID    int64
	chatTitle string
	seq       int64
	pending   map[int64]*captchaChallenge // by user id
	passed    map[int64]time.Time         // answered in DM before the join, by user id
}

func newCaptcha(api TbAPI, cfg CaptchaConfig) *captcha {
	return &captcha{tbAPI: api, cfg: cfg, pending: map[int64]*captchaChallenge{}, passed: map[int64]time.Time{}}
}

// SetConfig replaces the captcha config, questions already asked keep their own settings
func (c *captcha) SetConfig(cfg CaptchaConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg
}

func (c *captcha) config() CaptchaConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

func (c *captcha) setChat(id int64, title string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chatID, c.chatTitle = id, title
}

// OnJoinRequest asks the question in DM to someone asking to join the group.
// if the bot can't write to them the request is approved and the question is asked in the group after the join.
func (c *captcha) OnJoinRequest(req *tbapi.ChatJoinRequest) {
	cfg := c.config()
	c.mu.Lock()
	chatID := c.chatID
	_, busy := c.pending[req.From.ID]
	c.mu.Unlock()
	if !cfg.Ready() || req.Chat.ID != chatID || busy || req.From.IsBot {
		return
	}
	if c.skip(req.From.UserName, req.From.ID) {
		c.approve(req.From.ID)
		return
	}
	dmChat := req.UserChatID
	if dmChat == 0 {
		dmChat = req.From.ID
	}
	ch := c.newChallenge(cfg, &req.From)
	ch.joinRequest, ch.viaDM, ch.msgChatID = true, true, dmChat
	msgID, err := c.sendQuestion(cfg, ch, dmChat)
	if err != nil {
		log.Printf("[INFO] captcha: can't ask %s in DM, approving the request for a group question: %v", ch.name, err)
		c.approve(req.From.ID)
		return
	}
	ch.msgID = msgID
	c.track(ch, cfg.Timeout)
	log.Printf("[INFO] captcha: asked join request of %s (%d) in DM", ch.name, ch.userID)
}

// OnNewMember mutes a new member of the primary group and asks the question, in DM if possible
func (c *captcha) OnNewMember(member *tbapi.User) {
	cfg := c.config()
	if !cfg.Ready() || member.IsBot {
		return
	}
	c.mu.Lock()
	chatID := c.chatID
	_, busy := c.pending[member.ID]
	passedAt, passed := c.passed[member.ID]
	delete(c.passed, member.ID)
	c.mu.Unlock()
	if busy || (passed && time.Since(passedAt) < passedTTL) || c.skip(member.UserName, member.ID) {
		return
	}

	// the mute ends by itself shortly after the timeout, so a restart never leaves anyone muted for good
	if err := c.restrict(member.ID, time.Now().Add(cfg.Timeout+time.Minute)); err != nil {
		log.Printf("[WARN] captcha: can't mute %d, question skipped: %v", member.ID, err)
		return
	}

	ch := c.newChallenge(cfg, member)
	msgID, err := c.sendQuestion(cfg, ch, member.ID)
	if err == nil {
		ch.viaDM, ch.msgChatID = true, member.ID
	} else {
		log.Printf("[DEBUG] captcha: no DM to %d (%v), asking in the group", member.ID, err)
		if msgID, err = c.sendQuestion(cfg, ch, chatID); err != nil {
			log.Printf("[WARN] captcha: can't ask %s, lifting the mute: %v", ch.name, err)
			c.unrestrict(member.ID)
			return
		}
		ch.msgChatID = chatID
	}
	ch.msgID = msgID
	c.track(ch, cfg.Timeout)
	where := "group"
	if ch.viaDM {
		where = "DM"
	}
	log.Printf("[INFO] captcha: asked new member %s (%d) in %s", ch.name, ch.userID, where)
}

// OnLeft drops the question of a member who left before answering
func (c *captcha) OnLeft(userID int64) {
	c.mu.Lock()
	ch, ok := c.pending[userID]
	if ok && !ch.joinRequest {
		delete(c.pending, userID)
		ch.timer.Stop()
	}
	c.mu.Unlock()
	if ok && !ch.joinRequest {
		c.deleteMsg(ch)
	}
}

// IsCallback tells if the callback data belongs to a captcha button
func (c *captcha) IsCallback(data string) bool {
	return strings.HasPrefix(data, captchaCallbackPrefix)
}

// OnCallback handles a press on a captcha button, data is "Q:<user>:<seq>:<option>"
func (c *captcha) OnCallback(query *tbapi.CallbackQuery) error {
	parts := strings.Split(strings.TrimPrefix(query.Data, captchaCallbackPrefix), ":")
	if len(parts) != 3 {
		return fmt.Errorf("bad captcha callback %q", query.Data)
	}
	userID, err1 := strconv.ParseInt(parts[0], 10, 64)
	seq, err2 := strconv.ParseInt(parts[1], 10, 64)
	option, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("bad captcha callback %q", query.Data)
	}

	if query.From == nil || query.From.ID != userID {
		c.answerCallback(query.ID, c.config().NotYours, true)
		return nil
	}

	c.mu.Lock()
	ch, ok := c.pending[userID]
	if !ok || ch.seq != seq {
		c.mu.Unlock()
		c.answerCallback(query.ID, "", false)
		return nil
	}
	delete(c.pending, userID)
	ch.timer.Stop()
	c.mu.Unlock()

	if option == ch.correct {
		c.answerCallback(query.ID, ch.passMsg, false)
		c.pass(ch)
		return nil
	}
	c.answerCallback(query.ID, ch.failMsg, false)
	c.fail(ch, "wrong answer")
	return nil
}

func (c *captcha) onTimeout(userID, seq int64) {
	c.mu.Lock()
	ch, ok := c.pending[userID]
	if !ok || ch.seq != seq {
		c.mu.Unlock()
		return
	}
	delete(c.pending, userID)
	c.mu.Unlock()
	c.fail(ch, "no answer")
}

func (c *captcha) pass(ch *captchaChallenge) {
	log.Printf("[INFO] captcha: %s (%d) answered correctly", ch.name, ch.userID)
	c.finishMsg(ch, ch.passMsg)
	if ch.joinRequest {
		c.mu.Lock()
		c.passed[ch.userID] = time.Now()
		c.mu.Unlock()
		c.approve(ch.userID)
		return
	}
	c.unrestrict(ch.userID)
}

func (c *captcha) fail(ch *captchaChallenge, why string) {
	log.Printf("[INFO] captcha: %s (%d) failed (%s), action %s", ch.name, ch.userID, why, ch.failAction)
	c.finishMsg(ch, ch.failMsg)
	if c.dry {
		return
	}
	c.mu.Lock()
	chatID := c.chatID
	c.mu.Unlock()

	if ch.joinRequest {
		c.request(tbapi.DeclineChatJoinRequest{ChatConfig: tbapi.ChatConfig{ChatID: chatID}, UserID: ch.userID}, "decline")
		if ch.failAction == CaptchaFailBan {
			c.request(tbapi.BanChatMemberConfig{ChatMemberConfig: tbapi.ChatMemberConfig{
				ChatConfig: tbapi.ChatConfig{ChatID: chatID}, UserID: ch.userID}}, "ban")
		}
		return
	}

	switch ch.failAction {
	case CaptchaFailMute:
		_ = c.restrict(ch.userID, time.Time{})
	case CaptchaFailBan:
		c.request(tbapi.BanChatMemberConfig{ChatMemberConfig: tbapi.ChatMemberConfig{
			ChatConfig: tbapi.ChatConfig{ChatID: chatID}, UserID: ch.userID}}, "ban")
	default:
		c.request(tbapi.BanChatMemberConfig{ChatMemberConfig: tbapi.ChatMemberConfig{
			ChatConfig: tbapi.ChatConfig{ChatID: chatID}, UserID: ch.userID}}, "kick")
		c.request(tbapi.UnbanChatMemberConfig{ChatMemberConfig: tbapi.ChatMemberConfig{
			ChatConfig: tbapi.ChatConfig{ChatID: chatID}, UserID: ch.userID}, OnlyIfBanned: true}, "unban after kick")
	}
}

// finishMsg replaces the question in DM with the result, a question in the group is deleted
func (c *captcha) finishMsg(ch *captchaChallenge, text string) {
	if !ch.viaDM || strings.TrimSpace(text) == "" {
		c.deleteMsg(ch)
		return
	}
	edit := tbapi.NewEditMessageText(ch.msgChatID, ch.msgID, text)
	if _, err := c.tbAPI.Send(edit); err != nil {
		log.Printf("[DEBUG] captcha: can't edit DM question %d: %v", ch.msgID, err)
		c.deleteMsg(ch)
	}
}

func (c *captcha) deleteMsg(ch *captchaChallenge) {
	if ch.msgID == 0 {
		return
	}
	c.request(tbapi.DeleteMessageConfig{ChatID: ch.msgChatID, MessageID: ch.msgID}, "delete question")
}

func (c *captcha) newChallenge(cfg CaptchaConfig, u *tbapi.User) *captchaChallenge {
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if name == "" {
		name = u.UserName
	}
	if name == "" {
		name = strconv.FormatInt(u.ID, 10)
	}
	c.mu.Lock()
	c.seq++
	seq := c.seq
	c.mu.Unlock()
	return &captchaChallenge{userID: u.ID, name: name, seq: seq, correct: cfg.Answer - 1,
		failAction: cfg.FailAction, failMsg: cfg.FailMsg, passMsg: cfg.PassMsg}
}

func (c *captcha) track(ch *captchaChallenge, timeout time.Duration) {
	userID, seq := ch.userID, ch.seq
	c.mu.Lock()
	ch.timer = time.AfterFunc(timeout, func() { c.onTimeout(userID, seq) })
	c.pending[userID] = ch
	c.mu.Unlock()
}

// sendQuestion posts the question with one button per option and returns the message id
func (c *captcha) sendQuestion(cfg CaptchaConfig, ch *captchaChallenge, chatID int64) (int, error) {
	c.mu.Lock()
	title := c.chatTitle
	c.mu.Unlock()

	mention := fmt.Sprintf(`<a href="tg://user?id=%d">%s</a>`, ch.userID, html.EscapeString(ch.name))
	secs := int(cfg.Timeout.Round(time.Second).Seconds())
	repl := strings.NewReplacer("{name}", mention, "{group}", html.EscapeString(title),
		"{seconds}", strconv.Itoa(secs), "{minutes}", strconv.Itoa((secs+59)/60))

	var text strings.Builder
	if intro := strings.TrimSpace(cfg.Intro); intro != "" {
		text.WriteString(repl.Replace(html.EscapeString(intro)))
		text.WriteString("\n\n")
	}
	text.WriteString("<b>" + html.EscapeString(cfg.Question) + "</b>")

	order := make([]int, len(cfg.Options))
	for i := range order {
		order[i] = i
	}
	if cfg.Shuffle {
		rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	}
	rows := make([][]tbapi.InlineKeyboardButton, 0, len(order))
	for _, idx := range order {
		data := fmt.Sprintf("%s%d:%d:%d", captchaCallbackPrefix, ch.userID, ch.seq, idx)
		rows = append(rows, tbapi.NewInlineKeyboardRow(tbapi.NewInlineKeyboardButtonData(cfg.Options[idx], data)))
	}

	msg := tbapi.NewMessage(chatID, text.String())
	msg.ParseMode = tbapi.ModeHTML
	msg.ReplyMarkup = tbapi.NewInlineKeyboardMarkup(rows...)
	msg.LinkPreviewOptions = tbapi.LinkPreviewOptions{IsDisabled: true}
	sent, err := c.tbAPI.Send(msg)
	if err != nil {
		return 0, fmt.Errorf("send question: %w", err)
	}
	return sent.MessageID, nil
}

func (c *captcha) skip(userName string, userID int64) bool {
	if c.isSuper != nil && c.isSuper(userName, userID) {
		return true
	}
	return c.isApproved != nil && c.isApproved(userID)
}

func (c *captcha) restrict(userID int64, until time.Time) error {
	if c.dry {
		return nil
	}
	c.mu.Lock()
	chatID := c.chatID
	c.mu.Unlock()
	cfg := tbapi.RestrictChatMemberConfig{
		ChatMemberConfig: tbapi.ChatMemberConfig{ChatConfig: tbapi.ChatConfig{ChatID: chatID}, UserID: userID},
		Permissions:      &tbapi.ChatPermissions{},
	}
	if !until.IsZero() {
		cfg.UntilDate = until.Unix()
	}
	if _, err := c.tbAPI.Request(cfg); err != nil {
		return fmt.Errorf("restrict %d: %w", userID, err)
	}
	return nil
}

// unrestrict gives back the group's default rights
func (c *captcha) unrestrict(userID int64) {
	if c.dry {
		return
	}
	c.mu.Lock()
	chatID := c.chatID
	c.mu.Unlock()
	c.request(tbapi.RestrictChatMemberConfig{
		ChatMemberConfig: tbapi.ChatMemberConfig{ChatConfig: tbapi.ChatConfig{ChatID: chatID}, UserID: userID},
		Permissions: &tbapi.ChatPermissions{
			CanSendMessages: true, CanSendAudios: true, CanSendDocuments: true, CanSendPhotos: true,
			CanSendVideos: true, CanSendVideoNotes: true, CanSendVoiceNotes: true, CanSendPolls: true,
			CanSendOtherMessages: true, CanAddWebPagePreviews: true, CanReactToMessages: true,
			CanChangeInfo: true, CanInviteUsers: true, CanPinMessages: true, CanManageTopics: true,
		},
	}, "lift mute")
}

func (c *captcha) approve(userID int64) {
	if c.dry {
		return
	}
	c.mu.Lock()
	chatID := c.chatID
	c.mu.Unlock()
	c.request(tbapi.ApproveChatJoinRequestConfig{ChatConfig: tbapi.ChatConfig{ChatID: chatID}, UserID: userID}, "approve")
}

func (c *captcha) answerCallback(id, text string, alert bool) {
	cb := tbapi.NewCallback(id, text)
	cb.ShowAlert = alert && text != ""
	if _, err := c.tbAPI.Request(cb); err != nil {
		log.Printf("[DEBUG] captcha: can't answer callback: %v", err)
	}
}

func (c *captcha) request(cfg tbapi.Chattable, what string) {
	if _, err := c.tbAPI.Request(cfg); err != nil {
		log.Printf("[WARN] captcha: %s failed: %v", what, err)
	}
}
