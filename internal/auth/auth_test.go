package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret-key-at-least-32-bytes-long"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	if token == "" {
		t.Fatal("MakeJWT returned empty token")
	}
}

func TestValidateJWT_Success(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret-key-at-least-32-bytes-long"
	expiresIn := time.Hour

	// Create a token
	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	// Validate it
	parsedUserID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}

	if parsedUserID != userID {
		t.Errorf("Expected userID %v, got %v", userID, parsedUserID)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret-key-at-least-32-bytes-long"
	expiresIn := -time.Hour // Token expired 1 hour ago

	// Create an expired token
	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	// Try to validate it - should fail
	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatal("ValidateJWT should have rejected expired token")
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := uuid.New()
	correctSecret := "test-secret-key-at-least-32-bytes-long"
	wrongSecret := "wrong-secret-key-at-least-32-bytes-long"
	expiresIn := time.Hour

	// Create a token with correct secret
	token, err := MakeJWT(userID, correctSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	// Try to validate with wrong secret - should fail
	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatal("ValidateJWT should have rejected token signed with different secret")
	}
}

func TestValidateJWT_InvalidToken(t *testing.T) {
	secret := "test-secret-key-at-least-32-bytes-long"
	invalidToken := "this.is.not.a.valid.jwt"

	_, err := ValidateJWT(invalidToken, secret)
	if err == nil {
		t.Fatal("ValidateJWT should have rejected invalid token format")
	}
}

func TestValidateJWT_EmptyToken(t *testing.T) {
	secret := "test-secret-key-at-least-32-bytes-long"

	_, err := ValidateJWT("", secret)
	if err == nil {
		t.Fatal("ValidateJWT should have rejected empty token")
	}
}

func TestValidateJWT_ShortLivedToken(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret-key-at-least-32-bytes-long"
	expiresIn := 500 * time.Millisecond

	// Create a short-lived token
	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	// Should be valid immediately
	parsedUserID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT failed for fresh token: %v", err)
	}
	if parsedUserID != userID {
		t.Errorf("Expected userID %v, got %v", userID, parsedUserID)
	}

	// Wait for token to expire
	time.Sleep(1000 * time.Millisecond)

	// Should now be invalid
	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatal("ValidateJWT should have rejected expired token")
	}
}
