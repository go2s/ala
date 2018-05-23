package main

import (
	"strings"
	"github.com/aws/aws-lambda-go/lambda"
	"context"
	"errors"
)

type Statement struct {
	Action   string
	Effect   string
	Resource string
}

type PolicyDocument struct {
	Version   string
	Statement []*Statement
}

type Context struct {
	StringKey  string `json:"StringKey,omitempty"`
	NumberKey  int64  `json:"NumberKey,omitempty"`
	BooleanKey bool   `json:"BooleanKey,omitempty"`
}

type AuthResponse struct {
	PrincipalId    string          `json:"principalId,omitempty"`
	PolicyDocument *PolicyDocument `json:"policyDocument,omitempty"`
	Context        *Context        `json:"context,omitempty"`
}

func generatePolicy(principalId string, effect string, resource string) *AuthResponse {
	authResponse := &AuthResponse{}
	authResponse.PrincipalId = principalId

	if len(effect) > 0 && len(resource) > 0 {
		policyDocument := &PolicyDocument{}
		authResponse.PolicyDocument = policyDocument

		policyDocument.Version = "2012-10-17" // default version

		statementOne := &Statement{}
		statementOne.Action = "execute-api:Invoke" // default action
		statementOne.Effect = effect
		statementOne.Resource = resource

		policyDocument.Statement = append(policyDocument.Statement, statementOne)
	}

	authResponse.Context = &Context{}
	// Can optionally return a context object of your choosing.
	authResponse.Context.StringKey = "stringval"
	authResponse.Context.NumberKey = 123
	authResponse.Context.BooleanKey = true

	return authResponse
}

// AuthHandle provides an API Gateway Custom Authorizers.
// This is not a production code and is just provided as an example.
//
// Please refer to the full documentation for more information:
// https://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html

type Authorizer struct {
	AuthorizationToken string
	MethodArn          string
	Type               string
}

// Handle provides an API Gateway Custom Authorizers.
// This is not a production code and is just provided as an example.
//
// Please refer to the full documentation for more information:
// https://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html
func Handle(ctx context.Context, evt *Authorizer) (*AuthResponse, error) {
	switch token := strings.ToLower(evt.AuthorizationToken); token {
	case "allow":
		return generatePolicy("user", "Allow", evt.MethodArn), nil
	case "deny":
		return generatePolicy("user", "Deny", evt.MethodArn), nil
	case "unauthorized":
		return nil, errors.New("Unauthorized") // Return a 401 Unauthorized response
	default:
		return nil, errors.New("Error: Invalid token")
	}
}

func main() {
	lambda.Start(Handle)
}
