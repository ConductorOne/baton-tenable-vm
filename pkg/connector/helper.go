package connector

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/crypto"
	"github.com/conductorone/baton-tenable-vm/pkg/client"
	"google.golang.org/protobuf/types/known/structpb"
)

const symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

// Field keys shared across resource profiles, action schemas, and log fields.
const (
	fieldName    = "name"
	fieldUUID    = "uuid"
	fieldUserID  = "user_id"
	fieldSuccess = "success"
)

func isPasswordValid(password string) bool {
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case strings.ContainsRune(symbols, c):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// generateCredentials if the credential option is "Random Password", it returns a randomly generated password.
func generateCredentials(credentialOptions *v2.LocalCredentialOptions) (string, error) {
	if credentialOptions.GetRandomPassword() == nil {
		return "", errors.New("unsupported credential option")
	}

	const maxAttempts = 20
	for i := 0; i < maxAttempts; i++ {
		password, err := crypto.GenerateRandomPassword(
			&v2.LocalCredentialOptions_RandomPassword{
				Length: min(12, credentialOptions.GetRandomPassword().GetLength()),
			},
		)
		if err != nil {
			return "", err
		}
		if isPasswordValid(password) {
			return password, nil
		}
	}

	return "", errors.New("failed to generate a valid password after 20 attempts")
}

func getUserResourceId(uuid string, usersByUUID map[string]client.User) (*v2.ResourceId, error) {
	user, ok := usersByUUID[uuid]
	if !ok {
		return nil, fmt.Errorf("user not found, unknown UUID: %s", uuid)
	}
	return &v2.ResourceId{
		ResourceType: userResourceType.Id,
		Resource:     strconv.Itoa(user.ID),
	}, nil
}

func getGroupResourceId(uuid string, groupsByUUID map[string]string) (*v2.ResourceId, error) {
	groupID, ok := groupsByUUID[uuid]
	if !ok {
		return nil, fmt.Errorf("group not found, unknown UUID: %s", uuid)
	}
	return &v2.ResourceId{
		ResourceType: groupResourceType.Id,
		Resource:     groupID,
	}, nil
}

// extractActionUserID accepts either a number (IntField schema) or a string
// (CLI / account-status-lifecycle-test pass a string via jq --arg).
func extractActionUserID(v *structpb.Value) (string, error) {
	if v == nil {
		return "", fmt.Errorf("user id is nil")
	}
	switch k := v.GetKind().(type) {
	case *structpb.Value_NumberValue:
		return strconv.Itoa(int(k.NumberValue)), nil
	case *structpb.Value_StringValue:
		if k.StringValue == "" {
			return "", fmt.Errorf("user id is empty")
		}
		return k.StringValue, nil
	default:
		return "", fmt.Errorf("user id must be a number or string")
	}
}
