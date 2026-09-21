package auth

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		header      http.Header
		expectedKey string
		wantErr     error
	}{
		{
			name:        "valid key",
			header:      http.Header{"Authorization": []string{"ApiKey Fuwawa"}},
			expectedKey: "Fuwawa",
		},
		{
			name:        "valid secret key",
			header:      http.Header{"Authorization": []string{"ApiKey Secret_Api_Key"}},
			expectedKey: "Secret_Api_Key",
		},
		{
			name:    "missing header",
			header:  http.Header{},
			wantErr: ErrNoAuthHeaderIncluded, // from the auth package, not redeclared
		},
		{
			name:    "malformed header",
			header:  http.Header{"Authorization": []string{"Fuwawa"}},
			wantErr: ErrMalformedHeader, // whatever your package returns
		},
	}

	for _, testCase := range tests {
		key, err := GetAPIKey(testCase.header)

		if testCase.wantErr != nil {
			fmt.Printf("Want err %v, got err %v\n", testCase.wantErr, err)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("expected error %v, got %v", testCase.wantErr, err)
			}
			continue
		}

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != testCase.expectedKey {
			t.Fatalf("expected %q, got %q", testCase.expectedKey, key)
		}
	}
}
