package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/solsw/errorhelper"
	"github.com/solsw/cloudru/auth"
	"github.com/solsw/cloudru/keymanager"
)

func keysTest(t *auth.Token) error {
	// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws/signer/v4#pkg-overview
	parentId := os.Getenv("CLOUDRU_PARENT_ID")
	if parentId == "" {
		return errorhelper.CallerError(errors.New("no Parent Id"))
	}
	if err := auth.VetToken(context.Background(), t); err != nil {
		return errorhelper.CallerError(err)
	}

	ko, err := keymanager.GetAllKeys(context.Background(), t.AccessToken, parentId, 0, 0)
	if err != nil {
		return errorhelper.CallerError(err)
	}
	bb, _ := json.MarshalIndent(ko, "", "  ")
	fmt.Println(string(bb))

	k, err := keymanager.GetKey(context.Background(), t.AccessToken, ko.Keys[0].Id)
	if err != nil {
		return errorhelper.CallerError(err)
	}
	bb, _ = json.MarshalIndent(k, "", "  ")
	fmt.Println(string(bb))

	return nil
}
