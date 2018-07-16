// authors: wangoo
// created: 2018-05-23
// test mock

package main

import (
	"testing"
	"fmt"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/go2s/ala/auth"
)

func TestHandle(t *testing.T) {
	auth := &auth.Authorizer{
		AuthorizationToken: "allow",
		MethodArn:          "arn:aws-cn:execute-api:cn-north-1:638953167227:gxa3v62znk/null/GET/",
		Type:               "TOKEN",
	}
	res, err := Handle(nil, auth)
	assert.Nil(t, err, err)

	assert.Equal(t, "Allow", res.PolicyDocument.Statement[0].Effect, "Effect should be Allow")

	response, err := json.Marshal(res)
	fmt.Println(string(response))
}
