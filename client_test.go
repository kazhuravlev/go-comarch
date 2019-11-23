package comarch_test

import (
	"github.com/kazhuravlev/lib-comarch/comarch"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

const (
	testBasePath = "http://1.1.1.1"
	testUsername = "username"
	testPassword = "password"

	testCredentialsCardNo   = "1111222233334444"
	testCredentialsPassword = "123456"
)

var (
	log = logrus.New()
)

func TestNew(t *testing.T) {
	c, err := comarch.New(log, testBasePath, testUsername, testPassword, nil)
	assert.Nil(t, err)
	assert.NotNil(t, c)
}

func TestNewWithClient(t *testing.T) {
	c, err := comarch.New(log, testBasePath, testUsername, testPassword, http.DefaultClient)
	assert.Nil(t, err)
	assert.NotNil(t, c)
}

func TestClient_SignInByCard(t *testing.T) {
	c, _ := comarch.New(log, testBasePath, testUsername, testPassword, &http.Client{Timeout: time.Second * 1})

	accessToken, err := c.SignInByCard(testCredentialsCardNo, testCredentialsPassword)
	assert.Nil(t, err)
	assert.NotNil(t, accessToken)
	assert.True(t, len(accessToken.Cookies) > 0)
	assert.True(t, len(accessToken.Value) > 0)
}
