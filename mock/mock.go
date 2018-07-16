// aws lambda authorizer mock
// Handle provides an API Gateway Custom Authorizers.
// This is not a production code and is just provided as an example.
//
// Please refer to the full documentation for more information:
// https://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html
package main

import (
	"strings"
	"github.com/aws/aws-lambda-go/lambda"
	"context"
	"errors"
	"github.com/go2s/ala/auth"
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

	authResponse.Context = &auth.Context{}
	// Can optionally return a context object of your choosing.
	authResponse.Context.ClientID = "client1"
	authResponse.Context.Scope = "read,write"

	return authResponse
}

func Handle(ctx context.Context, evt *auth.Authorizer) (*auth.AuthResponse, error) {
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
