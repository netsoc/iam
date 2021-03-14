package email

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/netsoc/iam/pkg/models"
	mail "github.com/xhit/go-simple-mail/v2"
)

const (
	// VerificationSubject is the subject for verification emails
	VerificationSubject = "Netsoc account verification"
	// EmailResetPasswordSubject is the subject for password reset emails
	ResetPasswordSubject = "Netsoc account password reset"
)

var (
	// EmailVerificationAPI is a template for an email with API-based verification
	VerificationAPI = template.Must(template.New("email_verification.txt").Parse(`Hi {{.User.FirstName}},

Thanks for signing up to Netsoc! Here's your verification token: {{.Token}}

Regards,
The Netsoc Team
`))
	// EmailVerificationUI is a template for an email with UI-based verification
	VerificationUI = template.Must(template.New("email_verification.txt").Parse(`Hi {{.User.FirstName}},

Thanks for signing up to Netsoc! Click the following link to verify your account: {{template "url" .}}

Regards,
The Netsoc Team
`))

	// ResetPasswordAPI is a template for an email with API-based password reset
	ResetPasswordAPI = template.Must(template.New("email_verification.txt").Parse(`Hi {{.User.FirstName}},

Here's your password reset token: {{.Token}}

If you didn't initiate the reset, you can ignore this email.

Regards,
The Netsoc Team
`))
	// ResetPasswordUI is a template for an email with UI-based password reset
	ResetPasswordUI = template.Must(template.New("email_verification.txt").Parse(`Hi {{.User.FirstName}},

Click the following link to reset your password: {{template "url" .}}

If you didn't initiate the reset, you can ignore this email.

Regards,
The Netsoc Team
`))
)

// Config represents a Sender's configuration
type Config struct {
	From      string
	ReplyTo   string `mapstructure:"reply_to"`
	VerifyURL string `mapstructure:"verify_url"`
	ResetURL  string `mapstructure:"reset_url"`
}

// UserInfo represents information available to email templates
type UserInfo struct {
	User  *models.User
	Token string
}

type Sender interface {
	Config() *Config
	SendEmail(tpl *template.Template, subject string, info UserInfo) error
}

type SMTPConfig struct {
	Host     string
	Port     uint16
	Username string
	Password string
	TLS      bool

	PasswordFile string `mapstructure:"password_file"`
}

type SMTPSender struct {
	config Config
	smtp   *mail.SMTPServer
}

func NewSMTPSender(c Config, smtpConfig SMTPConfig) (*SMTPSender, error) {
	if _, err := VerificationUI.New("url").Parse(c.VerifyURL); err != nil {
		return nil, fmt.Errorf("failed to parse verification URL template")
	}
	if _, err := ResetPasswordUI.New("url").Parse(c.ResetURL); err != nil {
		return nil, fmt.Errorf("failed to parse password reset URL template")
	}

	m := &SMTPSender{
		smtp: mail.NewSMTPClient(),
	}

	m.smtp = mail.NewSMTPClient()
	m.smtp.Host = smtpConfig.Host
	m.smtp.Port = int(smtpConfig.Port)
	m.smtp.Username = smtpConfig.Username
	m.smtp.Password = smtpConfig.Password
	if smtpConfig.TLS {
		m.smtp.Encryption = mail.EncryptionTLS
	}

	return m, nil
}

func (m *SMTPSender) Config() *Config {
	return &m.config
}

// SendEmail sends an email to a user
func (m *SMTPSender) SendEmail(tpl *template.Template, subject string, info UserInfo) error {
	var b strings.Builder
	if err := tpl.Execute(&b, info); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	client, err := m.smtp.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}

	err = mail.NewMSG().
		SetFrom(m.config.From).
		SetReplyTo(m.config.ReplyTo).
		AddTo(fmt.Sprintf(`"%v %v" <%v>`, info.User.FirstName, info.User.LastName, info.User.Email)).
		SetSubject(subject).
		SetBody(mail.TextPlain, b.String()).
		Send(client)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}
