package server

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/netsoc/iam/pkg/models"
	mail "github.com/xhit/go-simple-mail/v2"
)

var (
	// EmailVerificationAPI is a template for an email with API-based verification
	EmailVerificationAPI = template.Must(template.New("email_verification.txt").Parse(`Hi {{.User.FirstName}},

Thanks for signing up to Netsoc! Here's your email verification token: {{.Token}}

Regards,
The Netsoc Team
`))
	// EmailVerificationUI is a template for an email with UI-based verification
	EmailVerificationUI = template.Must(template.New("email_verification.txt").Parse(`Hi {{.User.FirstName}},

Thanks for signing up to Netsoc! Click the following link to verify your account: {{template "url" .}}

Regards,
The Netsoc Team
`))

	// EmailResetPasswordAPI is a template for an email with API-based password reset
	EmailResetPasswordAPI = template.Must(template.New("email_verification.txt").Parse(`Hi {{.User.FirstName}},

Here's your password reset token: {{.Token}}

If you didn't initiate the reset, you can ignore this email.

Regards,
The Netsoc Team
`))
	// EmailResetPasswordUI is a template for an email with UI-based password reset
	EmailResetPasswordUI = template.Must(template.New("email_verification.txt").Parse(`Hi {{.User.FirstName}},

Click the following link to reset your password: {{template "url" .}}

If you didn't initiate the reset, you can ignore this email.

Regards,
The Netsoc Team
`))
)

func (s *Server) initEmail() error {
	if _, err := EmailVerificationUI.New("url").Parse(s.config.Mail.VerifyURL); err != nil {
		return fmt.Errorf("failed to parse verification URL template")
	}
	if _, err := EmailResetPasswordUI.New("url").Parse(s.config.Mail.ResetURL); err != nil {
		return fmt.Errorf("failed to parse password reset URL template")
	}

	s.smtp = mail.NewSMTPClient()
	s.smtp.Host = s.config.Mail.SMTP.Host
	s.smtp.Port = int(s.config.Mail.SMTP.Port)
	s.smtp.Username = s.config.Mail.SMTP.Username
	s.smtp.Password = s.config.Mail.SMTP.Password
	if s.config.Mail.SMTP.TLS {
		s.smtp.Encryption = mail.EncryptionTLS
	}

	return nil
}

// EmailUserInfo represents information available to email templates
type EmailUserInfo struct {
	User  *models.User
	Token string
}

// SendEmail sends an email to a user
func (s *Server) SendEmail(tpl *template.Template, subject string, info EmailUserInfo) error {
	var b strings.Builder
	if err := tpl.Execute(&b, info); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	client, err := s.smtp.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}

	err = mail.NewMSG().
		SetFrom(s.config.Mail.From).
		SetReplyTo(s.config.Mail.ReplyTo).
		AddTo(fmt.Sprintf(`"%v %v" <%v>`, info.User.FirstName, info.User.LastName, info.User.Email)).
		SetSubject(subject).
		SetBody(mail.TextPlain, b.String()).
		Send(client)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}
