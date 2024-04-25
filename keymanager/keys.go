package keymanager

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"github.com/solsw/errorhelper"
	"github.com/solsw/generichelper"
	"github.com/solsw/httphelper/rest"
)

const (
	baseUrl = "https://kms.api.sbercloud.ru/v1/keys"
)

type (
	Primary struct {
		Algorithm string `json:"algorithm,omitempty"`
		CreatedAt string `json:"createdAt,omitempty"`
		DestroyAt string `json:"destroyAt,omitempty"`
		Id        int    `json:"id,omitempty"`
		KeyId     string `json:"keyId,omitempty"`
		State     string `json:"state,omitempty"`
	}
	Key struct {
		// https://cloud.ru/ru/docs/kms/ug/topics/api-ref_key.html#
		CreatedAt        string   `json:"createdAt,omitempty"`
		DefaultAlgorithm string   `json:"defaultAlgorithm,omitempty"`
		Description      string   `json:"description,omitempty"`
		Id               string   `json:"id,omitempty"`
		Labels           []string `json:"labels,omitempty"`
		Name             string   `json:"name,omitempty"`
		NextRotationTime string   `json:"nextRotationTime,omitempty"`
		Owner            string   `json:"owner,omitempty"`
		Primary          Primary  `json:"primary,omitempty"`
		RotationPeriod   string   `json:"rotationPeriod,omitempty"`
		ParentId         string   `json:"parentId,omitempty"`
		UpdateMask       string   `json:"updateMask,omitempty"`
	}
	AllKeys struct {
		Keys []Key `json:"keys"`
	}
)

// GetAllKeys возвращает список всех существующих ключей.
func GetAllKeys(ctx context.Context, accessToken, parentId string, pageLimit, pageOffset int) (*AllKeys, error) {
	// https://cloud.ru/ru/docs/kms/ug/topics/api-ref_key.html#get--v1-keys
	if accessToken == "" {
		return nil, errorhelper.CallerError(errors.New("no accessToken"))
	}
	if parentId == "" {
		return nil, errorhelper.CallerError(errors.New("no parentId"))
	}
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+accessToken)
	q := make(url.Values)
	q.Set("parentId", parentId)
	if pageLimit > 0 {
		q.Set("page.limit", strconv.Itoa(pageLimit))
	}
	if pageOffset > 0 {
		q.Set("page.offset", strconv.Itoa(pageOffset))
	}
	u, _ := url.Parse(baseUrl)
	u.RawQuery = q.Encode()
	ko, err := rest.BodyJson[AllKeys, generichelper.NoType](ctx,
		http.DefaultClient,
		http.MethodGet,
		u.String(),
		h,
		nil,
		rest.IsNotStatusOK,
	)
	if err != nil {
		return nil, err
	}
	return ko, nil
}

// GetKey возвращает информацию об определённом ключе.
func GetKey(ctx context.Context, accessToken, keyId string) (*Key, error) {
	// https://cloud.ru/ru/docs/kms/ug/topics/api-ref_key.html#get--v1-keys-keyId
	if accessToken == "" {
		return nil, errorhelper.CallerError(errors.New("no accessToken"))
	}
	if keyId == "" {
		return nil, errorhelper.CallerError(errors.New("no keyId"))
	}
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+accessToken)
	u, _ := url.Parse(baseUrl)
	u.Path = path.Join(u.Path, keyId)
	k, err := rest.BodyJson[Key, generichelper.NoType](ctx,
		http.DefaultClient,
		http.MethodGet,
		u.String(),
		h,
		nil,
		rest.IsNotStatusOK,
	)
	if err != nil {
		return nil, errorhelper.CallerError(err)
	}
	return k, nil
}

// CreateKey создаёт ключ.
func CreateKey(ctx context.Context, accessToken string, key *Key) (*Key, error) {
	// https://cloud.ru/ru/docs/kms/ug/topics/api-ref_key.html#post--v1-keys
	// https://cloud.ru/ru/docs/kms/ug/topics/guids_key-management_create.html
	if accessToken == "" {
		return nil, errorhelper.CallerError(errors.New("no accessToken"))
	}
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+accessToken)
	k, err := rest.JsonJson[Key, Key, generichelper.NoType](ctx,
		http.DefaultClient,
		http.MethodPost,
		baseUrl,
		h,
		key,
		rest.IsNotStatusOK,
	)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// UpdateKey обновляет параметры ключа.
func UpdateKey(ctx context.Context, accessToken, keyId string, key *Key) (*Key, error) {
	// https://cloud.ru/ru/docs/kms/ug/topics/api-ref_key.html#patch--v1-keys-key.id
	// https://cloud.ru/ru/docs/kms/ug/topics/guids_key-management_edit.html#
	if accessToken == "" {
		return nil, errorhelper.CallerError(errors.New("no accessToken"))
	}
	if keyId == "" {
		return nil, errorhelper.CallerError(errors.New("no keyId"))
	}
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+accessToken)
	u, _ := url.Parse(baseUrl)
	u.Path = path.Join(u.Path, keyId)
	k, err := rest.JsonJson[Key, Key, generichelper.NoType](ctx,
		http.DefaultClient,
		http.MethodPatch,
		u.String(),
		h,
		key,
		rest.IsNotStatusOK,
	)
	if err != nil {
		return nil, errorhelper.CallerError(err)
	}
	return k, nil
}

// DeleteKey удаляет ключ.
func DeleteKey(ctx context.Context, accessToken, keyId string) error {
	// https://cloud.ru/ru/docs/kms/ug/topics/api-ref_key.html#delete--v1-keys-keyId
	// https://cloud.ru/ru/docs/kms/ug/topics/guids_key-management_delete.html#
	if accessToken == "" {
		return errorhelper.CallerError(errors.New("no accessToken"))
	}
	if keyId == "" {
		return errorhelper.CallerError(errors.New("no keyId"))
	}
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+accessToken)
	u, _ := url.Parse(baseUrl)
	u.Path = path.Join(u.Path, keyId)
	_, err := rest.BodyBody[generichelper.NoType](ctx,
		http.DefaultClient,
		http.MethodDelete,
		u.String(),
		h,
		nil,
		rest.IsNotStatusOK,
	)
	if err != nil {
		return errorhelper.CallerError(err)
	}
	return nil
}
