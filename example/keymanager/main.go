package main

import (
	"context"
	"errors"
	"os"

	"github.com/solsw/errorhelper"
	"github.com/solsw/cloudru/auth"
)

func getIdSecret() (string, string, error) {
	id := os.Getenv("CLOUDRU_KEY_ID")
	if id == "" {
		return "", "", errorhelper.CallerError(errors.New("no Key Id"))
	}
	secret := os.Getenv("CLOUDRU_KEY_SECRET")
	if secret == "" {
		return "", "", errorhelper.CallerError(errors.New("no Key Secret"))
	}
	return id, secret, nil
}

func main() {
	id, secret, err := getIdSecret()
	if err != nil {
		panic(err)
	}
	t, err := auth.NewToken(context.Background(), id, secret)
	if err != nil {
		panic(err)
	}
	var errs []error
	err = keysTest(t)
	errs = append(errs, err)
	if jerr := errors.Join(errs...); jerr != nil {
		panic(jerr)
	}
}
