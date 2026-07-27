package submitter

import (
	"testing"
)

func TestBucketMarshalJSON(t *testing.T) {
	tests := []struct {
		b    Bucket
		want string
	}{
		{EXCLUDED, `"EXCLUDED"`},
		{DISPREFERRED_MMDBLOWN, `"DISPREFERRED_MMDBLOWN"`},
		{DISPREFERRED_LOWUPTIME, `"DISPREFERRED_LOWUPTIME"`},
		{DISPREFERRED_RECENTBADRESPONSE, `"DISPREFERRED_RECENTBADRESPONSE"`},
		{DISPREFERRED_RECENTTIMEOUT, `"DISPREFERRED_RECENTTIMEOUT"`},
		{DISPREFERRED_RECENT5XX, `"DISPREFERRED_RECENT5XX"`},
		{DISPREFERRED_RECENT4XX, `"DISPREFERRED_RECENT4XX"`},
		{DISPREFERRED_SLOWRESPONSES, `"DISPREFERRED_SLOWRESPONSES"`},
		{NEUTRAL, `"NEUTRAL"`},
		{PREFERRED_BYCONFIG, `"PREFERRED_BYCONFIG"`},
		{Bucket(99), `"UNKNOWN"`},
	}
	for _, tt := range tests {
		b, err := tt.b.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON(%d): %v", tt.b, err)
		}
		if string(b) != tt.want {
			t.Errorf("Bucket(%d).MarshalJSON() = %s, want %s", tt.b, b, tt.want)
		}
	}
}
