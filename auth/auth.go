// authors: wangoo
// created: 2018-05-23
// aws lambda authorizer model definition

package auth

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
	ClientId string `json:"clientId,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type AuthResponse struct {
	PrincipalId    string          `json:"principalId,omitempty"`
	PolicyDocument *PolicyDocument `json:"policyDocument,omitempty"`
	Context        *Context        `json:"context,omitempty"`
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
