package submitter

import (
	"testing"
)

func TestLogTypeMarshalJSON(t *testing.T) {
	tests := []struct {
		lt   LogType
		want string
	}{
		{LOGTYPE_RFC6962, `"RFC6962"`},
		{LOGTYPE_STATIC, `"STATIC"`},
		{LogType(99), `"UNKNOWN"`},
	}
	for _, tt := range tests {
		b, err := tt.lt.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON(%d): %v", tt.lt, err)
		}
		if string(b) != tt.want {
			t.Errorf("LogType(%d).MarshalJSON() = %s, want %s", tt.lt, b, tt.want)
		}
	}
}
