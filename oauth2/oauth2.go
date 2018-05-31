// authors: wangoo
// created: 2018-05-30
// oauth2 aws lambda authorizer
// Handle provides an API Gateway Custom Authorizers.
// This is not a production code and is just provided as an example.
//
// Please refer to the full documentation for more information:
// https://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html

package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"context"
	"errors"
	"github.com/go-fast/lambda-auth/auth"
	"gopkg.in/oauth2.v3/models"
	"io/ioutil"
	"net/http"
	"log"
	"encoding/json"
)

func generatePolicy(principalId string, effect string, resource string) *auth.AuthResponse {
	authResponse := &auth.AuthResponse{}
	authResponse.PrincipalId = principalId

	if len(effect) > 0 && len(resource) > 0 {
		policyDocument := &auth.PolicyDocument{}
		authResponse.PolicyDocument = policyDocument

		policyDocument.Version = "2012-10-17" // default version

		statementOne := &auth.Statement{}
		statementOne.Action = "execute-api:Invoke" // default action
		statementOne.Effect = effect
		statementOne.Resource = resource

		policyDocument.Statement = append(policyDocument.Statement, statementOne)
	}

	return authResponse
}

func Handle(ctx context.Context, evt *auth.Authorizer) (*auth.AuthResponse, error) {
	token := evt.AuthorizationToken
	log.Printf("auth token: %v\n", token)

	req, err := http.NewRequest("GET", oauth2ValidUrl, nil)
	if err != nil {
		log.Println(err)
		return deny(evt)
	}
	req.Header.Set("Authorization", token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return deny(evt)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("auth status: %v\n", resp.StatusCode)
		return unauthorized()
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("auth failed err:%v\n", err)
		return deny(evt)
	}

	t := &models.Token{}
	err = json.Unmarshal(body, t)
	if err != nil {
		log.Printf("auth response parse err:%v\n", err)
		return deny(evt)
	}

	principalId := t.GetUserID()
	if principalId == "" {
		log.Printf("auth response:%v\n", string(body))
		return deny(evt)
	}
	log.Printf("auth principalId:%v\n", principalId)
	return allow(evt, principalId)
}

func allow(evt *auth.Authorizer, principalId string) (*auth.AuthResponse, error) {
	return generatePolicy(principalId, "Allow", evt.MethodArn), nil
}

func unauthorized() (*auth.AuthResponse, error) {
	return nil, errors.New("Unauthorized") // Return a 401 Unauthorized response
}

func deny(evt *auth.Authorizer) (*auth.AuthResponse, error) {
	return generatePolicy("", "Deny", evt.MethodArn), nil
}

func main() {
	lambda.Start(Handle)
}
