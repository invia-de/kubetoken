package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	keyring "github.com/zalando/go-keyring"
)

func TestKeyring(t *testing.T) {
	keyring.MockInit()
	user := "test-user"
	pass := "test-pass"

	// Test password not existing
	_, err := getKeyringPassword(user)
	assert.Equal(t, keyring.ErrNotFound, err)

	// Add the password
	err = setKeyringPassword(user, pass)
	assert.Nil(t, err)

	// Ensure the password exists
	password, err := getKeyringPassword(user)
	assert.Nil(t, err)
	assert.Equal(t, pass, password)
}

func TestGetPasswordFromKeyringFlow(t *testing.T) {
	keyring.MockInit()
	user := "test-user"
	pass := "test-pass"

	err := setKeyringPassword(user, pass)
	assert.Nil(t, err)

	password := getPassword(user, false, false)
	assert.Equal(t, pass, password)
}
