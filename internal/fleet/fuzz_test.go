package fleet

import (
	"encoding/json"
	"testing"
	"time"
)

func FuzzSignedDesiredStateParsing(f *testing.F) {
	d := testDesired(time.Now().UTC())
	wire, _ := json.Marshal(SignedDesiredState{State: d})
	f.Add(wire)
	f.Add([]byte(`{"state":{"format_version":1,"revision":1},"signature":"bad"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var envelope SignedDesiredState
		_ = json.Unmarshal(data, &envelope)
		_ = envelope.State.Validate(time.Now().UTC())
	})
}

func FuzzActionParsing(f *testing.F) {
	f.Add([]byte(`{"format_version":1,"action_id":"a","kind":"sync"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var action Action
		_ = json.Unmarshal(data, &action)
		_ = action.Validate(time.Now().UTC())
	})
}
