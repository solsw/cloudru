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
	parentId := os.Getenv("CLOUDRU_KEY_MANAGER_PARENT_ID")
	if parentId == "" {
		return errorhelper.CallerError(errors.New("no Key Manager Parent Id"))
	}
	if err := auth.VetToken(context.Background(), t); err != nil {
		return errorhelper.CallerError(err)
	}

	kk, err := keymanager.GetAllKeys(context.Background(), t.AccessToken, parentId, 0, 0)
	if err != nil {
		return errorhelper.CallerError(err)
	}
	bb, _ := json.MarshalIndent(kk, "", "  ")
	fmt.Println(string(bb))

	k, err := keymanager.GetKey(context.Background(), t.AccessToken, kk.Keys[0].Id)
	if err != nil {
		return errorhelper.CallerError(err)
	}
	bb, _ = json.MarshalIndent(k, "", "  ")
	fmt.Println(string(bb))

	return nil
}
