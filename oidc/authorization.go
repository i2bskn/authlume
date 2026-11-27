package oidc

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// AuthorizationOptions configures a single login from trusted application
// policy. The zero value requests the provider's normal sign-in.
type AuthorizationOptions struct {
	// MaxAgeSeconds requests a signed auth_time and limits its age at completion.
	// Zero requires authentication during this login. Nil omits max_age.
	MaxAgeSeconds *int64
	// ACRValues are ordered preferences. Check the actual signed ACR under
	// the linked account's policy before issuing a session.
	ACRValues []string
	// Prompt can be empty, none, login, consent or select_account.
	Prompt string
	// AppData is opaque application state, such as a validated return path,
	// stored with the server-side transaction and returned only after a
	// successful completion. It never reaches the browser or the provider.
	// It is limited to MaxAppData bytes. Validate it again after completion.
	AppData []byte
}

// MaxAppData is the largest AuthorizationOptions.AppData accepted.
const MaxAppData = 16 << 10

func (o AuthorizationOptions) parameters() ([]oauth2.AuthCodeOption, error) {
	var params []oauth2.AuthCodeOption
	if len(o.AppData) > MaxAppData {
		return nil, errors.New("oidc: app data too large")
	}
	if o.MaxAgeSeconds != nil {
		if *o.MaxAgeSeconds < 0 {
			return nil, errors.New("oidc: max_age must be nonnegative")
		}
		params = append(params, oauth2.SetAuthURLParam("max_age", strconv.FormatInt(*o.MaxAgeSeconds, 10)))
	}
	for _, value := range o.ACRValues {
		if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '!' || r > '~' }) >= 0 {
			return nil, errors.New("oidc: invalid acr_values entry")
		}
	}
	if len(o.ACRValues) != 0 {
		params = append(params, oauth2.SetAuthURLParam("acr_values", strings.Join(o.ACRValues, " ")))
	}
	switch o.Prompt {
	case "":
	case "none", "login", "consent", "select_account":
		params = append(params, oauth2.SetAuthURLParam("prompt", o.Prompt))
	default:
		return nil, errors.New("oidc: unsupported prompt")
	}
	return params, nil
}

func (tx Transaction) acceptsAuthTime(at, now time.Time) bool {
	if tx.MaxAgeSeconds == nil {
		return true
	}
	age := *tx.MaxAgeSeconds
	if age < 0 || at.IsZero() || at.Unix() < 0 || at.After(now) {
		return false
	}
	if age == 0 {
		// NumericDate has second precision. Network round trips can span
		// several seconds after the provider actively authenticated the user.
		return !tx.StartedAt.IsZero() && at.Unix() >= tx.StartedAt.Unix()
	}
	return now.Unix()-at.Unix() <= age
}
