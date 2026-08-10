package endpoint

import "testing"

func TestCheckPOSTEndpoint(t *testing.T) {
	if ep, ok := CheckPOSTEndpoint(ENDPOINTSTRING_ADDCHAIN); !ok || ep != ENDPOINT_ADDCHAIN {
		t.Fatalf("add-chain: got (%v, %v), want (%v, true)", ep, ok, ENDPOINT_ADDCHAIN)
	}
	if ep, ok := CheckPOSTEndpoint(ENDPOINTSTRING_ADDPRECHAIN); !ok || ep != ENDPOINT_ADDPRECHAIN {
		t.Fatalf("add-pre-chain: got (%v, %v), want (%v, true)", ep, ok, ENDPOINT_ADDPRECHAIN)
	}
	if _, ok := CheckPOSTEndpoint("not-an-endpoint"); ok {
		t.Fatal("expected ok=false for an unknown endpoint")
	}
}

func TestAPIEndpointMapping(t *testing.T) {
	if got := APIEndpoint[ENDPOINT_ADDCHAIN]; got != ENDPOINTSTRING_ADDCHAIN {
		t.Errorf("APIEndpoint[ADDCHAIN]: got %q, want %q", got, ENDPOINTSTRING_ADDCHAIN)
	}
	if got := APIEndpoint[ENDPOINT_ADDPRECHAIN]; got != ENDPOINTSTRING_ADDPRECHAIN {
		t.Errorf("APIEndpoint[ADDPRECHAIN]: got %q, want %q", got, ENDPOINTSTRING_ADDPRECHAIN)
	}
}
