// authors: wangoo
// created: 2018-05-23
// test mock

package main

import (
	"testing"
	"fmt"
	"encoding/json"
)

func TestHandle(t *testing.T) {
	auth := &Authorizer{
		AuthorizationToken: "allow",
		MethodArn:          "arn:aws-cn:execute-api:cn-north-1:638953167227:gxa3v62znk/null/GET/",
		Type:               "TOKEN",
	}
	res, err := Handle(nil, auth)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(res)
	response, err := json.Marshal(res)
	fmt.Println(string(response))

}
