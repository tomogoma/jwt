package jwt_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	jwtH "github.com/tomogoma/jwt"
)

const (
	authKey    = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDlfPOhsFGRDCC3"
	authKeyAlt = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDGygyp2ZlaQq6D"
)

type ClaimsMock struct {
	UserID int64
	jwt.StandardClaims
}

func TestNewJWTHandler(t *testing.T) {
	type testCase struct {
		name   string
		key    []byte
		expErr bool
	}
	tcs := []testCase{
		{
			name:   "valid",
			key:    []byte(authKey),
			expErr: false,
		},
		{
			name:   "empty key",
			key:    []byte(""),
			expErr: true,
		},
		{
			name:   "nil key",
			key:    nil,
			expErr: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tg, err := jwtH.NewHandler(tc.key)
			if tc.expErr {
				if err == nil {
					t.Errorf("%s - expected an error but got nil", tc.name)
				}
				return
			}
			if err != nil {
				t.Errorf("%s token.NewHandler(): %v", tc.name, err)
				return
			}
			if tg == nil {
				t.Errorf("%s - got nil generator", tc.name)
			}
		})
	}
}

func TestJWTHandler_Validate(t *testing.T) {

	claims := ClaimsMock{
		UserID: 256,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
			Id:        `{"service":"test","user":64}`,
		},
	}

	tg, err := jwtH.NewHandler([]byte(authKey))
	if err != nil {
		t.Fatalf("Error setting up: token.NewHandler(): %v", err)
	}
	tkn, err := tg.Generate(claims)
	if err != nil {
		t.Fatalf("Error setting up token.Handler#Generate(): %v", err)
	}
	tgInvalid, err := jwtH.NewHandler([]byte(authKeyAlt))
	if err != nil {
		t.Fatalf("Error setting up: token.NewHandler(): %v", err)
	}
	tknInvalid, err := tgInvalid.Generate(claims)
	if err != nil {
		t.Fatalf("Error setting up token.Handler#Generate(): %v", err)
	}

	tcs := []struct {
		name            string
		token           string
		passClaims      jwt.Claims
		expErr          bool
		expUnauthorized bool
		expForbidden    bool
	}{
		{
			name:       "valid pass claims",
			token:      tkn,
			passClaims: &ClaimsMock{},
			expErr:     false,
		},
		{
			name:       "valid pass nil claims",
			token:      tkn,
			passClaims: nil,
			expErr:     true,
		},
		{
			name:            "empty token",
			token:           "",
			passClaims:      &ClaimsMock{},
			expErr:          true,
			expForbidden:    false,
			expUnauthorized: true,
		},
		{
			name:            "invalid signing key",
			token:           tknInvalid,
			passClaims:      &ClaimsMock{},
			expErr:          true,
			expForbidden:    true,
			expUnauthorized: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tkn, err := tg.Validate(tc.token, tc.passClaims)
			if tc.expErr {
				if err == nil {
					t.Fatal("Expected an error, got nil")
				}
				if tc.expForbidden != tg.IsForbiddenError(err) {
					t.Errorf("Expected IsForbiddenError %t, got %t",
						tc.expForbidden, tg.IsForbiddenError(err))
				}
				if tc.expUnauthorized != tg.IsUnauthorizedError(err) {
					t.Errorf("Expected IsForbiddenError %t, got %t",
						tc.expUnauthorized, tg.IsUnauthorizedError(err))
				}
				return
			}
			if err != nil {
				t.Fatalf("Got error: %v", err)
			}
			if tc.passClaims != nil && !reflect.DeepEqual(&claims, tc.passClaims) {
				t.Errorf("Extracted claims mismatch:\nExpect:\t%+v\nGot:\t%+v",
					claims, tc.passClaims)
			}
			if tkn == nil {
				t.Fatalf("Received nil JWT")
			}
		})
	}
}
