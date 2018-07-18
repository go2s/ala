// authors: wangoo
// created: 2018-05-30
// oauth2 aws lambda authorizer
// Handle provides an API Gateway Custom Authorizers.
// This is not a production code and is just provided as an example.
//
// Please refer to the full documentation for more information:
// https://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html
// ---------------------
// lambda received authorizer header information:
// {
//    "accountId": "638953167227",
//    "resourceId": "666khp",
//    "stage": "_live_qa",
//    "requestId": "77e31d8f-8a36-11e8-aec2-4b0469ed4b35",
//    "identity": {
//        "cognitoIdentityPoolId": "",
//        "accountId": "",
//        "cognitoIdentityId": "",
//        "caller": "",
//        "apiKey": "",
//        "sourceIp": "117.30.209.12",
//        "cognitoAuthenticationType": "",
//        "cognitoAuthenticationProvider": "",
//        "userArn": "",
//        "userAgent": "PostmanRuntime/7.1.5",
//        "user": ""
//    },
//    "resourcePath": "/a/{proxy+}",
//    "authorizer": {
//        "scope": "manage",
//        "clientId": "my_client",
//        "principalId": "5b39df0621c4694cc8d270ba"
//    },
//    "httpMethod": "GET",
//    "apiId": "333d27kbbe"
//}
package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"context"
	"errors"
	"github.com/go2s/ala/auth"
	"io/ioutil"
	"net/http"
	"log"
	"encoding/json"
	"strings"
	"github.com/go2s/o2x"
)

func ResetResourceScope(resource string, authPrefix string, authReplace string) string {
	idx := strings.Index(resource, authPrefix)
	if idx > 0 {
		return resource[:idx] + authReplace
	}
	return resource
}

func generatePolicy(principalId, clientID, scope string, effect string, resource string) *auth.AuthResponse {
	authResponse := &auth.AuthResponse{}
	authResponse.PrincipalId = principalId

	if len(effect) > 0 && len(resource) > 0 {
		policyDocument := &auth.PolicyDocument{}
		authResponse.PolicyDocument = policyDocument

		policyDocument.Version = "2012-10-17" // default version

		statementOne := &auth.Statement{}
		statementOne.Action = "execute-api:Invoke" // default action
		statementOne.Effect = effect
		statementOne.Resource = ResetResourceScope(resource, authResPrefix, authResReplace)
		log.Printf("policy: %v, %v\n", statementOne.Effect, statementOne.Resource)

		policyDocument.Statement = append(policyDocument.Statement, statementOne)
	}

	authResponse.Context = &auth.Context{}
	authResponse.Context.ClientId = clientID
	authResponse.Context.Scope = scope

	return authResponse
}

func allow(evt *auth.Authorizer, principalId, clientID, scope string) (*auth.AuthResponse, error) {
	return generatePolicy(principalId, clientID, scope, "Allow", evt.MethodArn), nil
}

func unauthorized() (*auth.AuthResponse, error) {
	return nil, errors.New("Unauthorized") // Return a 401 Unauthorized response
}

func internalError() (*auth.AuthResponse, error) {
	return nil, errors.New("InternalServerError")
}

func deny(evt *auth.Authorizer) (*auth.AuthResponse, error) {
	return generatePolicy("", "", "", "Deny", evt.MethodArn), nil
}

func Handle(ctx context.Context, evt *auth.Authorizer) (*auth.AuthResponse, error) {
	token := evt.AuthorizationToken
	log.Printf("auth request: %v, %v, %v \n", token, evt.MethodArn, evt.Type)

	if token == "" {
		return unauthorized()
	}

	req, err := http.NewRequest("GET", oauth2ValidUrl, nil)
	if err != nil {
		log.Println(err)
		return internalError()
	}
	req.Header.Set("Authorization", token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return internalError()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("auth status: %v\n", resp.StatusCode)
		return unauthorized()
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("auth failed err:%v\n", err)
		return internalError()
	}

	t := &o2x.ValidResponse{}
	err = json.Unmarshal(body, t)
	if err != nil {
		log.Printf("auth response parse err:%v\n", err)
		return internalError()
	}

	principalId := t.UserID
	if principalId == "" {
		log.Printf("auth response:%v\n", string(body))
		return deny(evt)
	}
	log.Printf("auth info:%v\n", t)
	return allow(evt, principalId, t.ClientID, t.Scope)
}

func main() {
	lambda.Start(Handle)
}
