package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/solsw/errorhelper"
	"github.com/solsw/generichelper"
	"github.com/solsw/httphelper/rest"
	"github.com/solsw/jwt"
)

// Токен доступа, возвращаемый по запросу к /auth/system/openid/token.
type Token struct {
	AccessToken     string `json:"access_token"`
	ExpiresIn       int    `json:"expires_in"`
	IdToken         string `json:"id_token"`
	NotBeforePolicy int    `json:"not-before-policy"`
	Scope           string `json:"scope"`
	TokenType       string `json:"token_type"`

	// Client Id
	id string
	// Client Secret
	secret string
}

// NewToken [возвращает] новый [Token].
//
// [возвращает]: https://cloud.ru/ru/docs/console_api/ug/topics/guides__auth_api.html
func NewToken(ctx context.Context, id, secret string) (*Token, error) {
	h := make(http.Header)
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	v := make(url.Values)
	v.Set("grant_type", "access_key")
	v.Set("client_id", id)
	v.Set("client_secret", secret)
	t, err := rest.BodyJson[Token, generichelper.NoType](ctx,
		http.DefaultClient,
		http.MethodPost,
		"https://auth.iam.sbercloud.ru/auth/system/openid/token",
		h,
		strings.NewReader(v.Encode()),
		rest.IsNotStatusOK,
	)
	if err != nil {
		return nil, errorhelper.CallerError(err)
	}
	t.id, t.secret = id, secret
	return t, nil
}

func expiration(t *Token) (time.Time, error) {
	ut, err := jwt.UnixTime(t.AccessToken, "exp")
	if err != nil {
		return time.Time{}, errorhelper.CallerError(err)
	}
	return time.Unix(ut, 0), nil
}

// VetToken обновляет [Token], если истёк его срок действия.
func VetToken(ctx context.Context, t *Token) error {
	if t == nil {
		return errorhelper.CallerError(errors.New("nil token"))
	}
	exp, err := expiration(t)
	if err != nil {
		return errorhelper.CallerError(err)
	}
	if time.Until(exp) > 1*time.Minute {
		return nil
	}
	// access token expired
	newt, err := NewToken(ctx, t.id, t.secret)
	if err != nil {
		return errorhelper.CallerError(err)
	}
	*t = *newt
	return nil
}
