// authors: wangoo
// created: 2018-06-01
// test

package main

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestResetResourceScope(t *testing.T) {
	res := "arn:aws-cn:execute-api:cn-north-1:aaaa:aaaa/qa/GET/template/management/e16674eb-4030-40c9-878e-e8940644ed7d"

	r := ResetResourceScope(res, "/qa/", "/qa/*")
	assert.Equal(t, "arn:aws-cn:execute-api:cn-north-1:aaaa:aaaa/qa/*", r)
}
