package decode

import (
	"reflect"
	"testing"
)

func FuzzDecoder(f *testing.F) {
	f.Add("P_L4K0", []byte(nil))
	f.Add("P_L4K0", []byte{6, 0, 0, 0, 0, 0, 0, 4, 2, 0, 1, 0, 'E', 0})
	f.Add("Provider_L5KffGgroup", []byte{4, 1, 0, 0, 0, 0, 0, 5})
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		run := func() ([]State, string) {
			enumerator, err := Start(name, data)
			if err != nil {
				return nil, err.Error()
			}
			states := make([]State, 0, 16)
			for enumerator.Next() {
				states = append(states, enumerator.State())
			}
			if err := enumerator.Err(); err != nil {
				return states, err.Error()
			}
			_, err = Decode(name, data)
			if err != nil {
				return states, err.Error()
			}
			return states, ""
		}
		firstStates, firstErr := run()
		secondStates, secondErr := run()
		if firstErr != secondErr || !reflect.DeepEqual(firstStates, secondStates) {
			t.Fatalf("nondeterministic result: %v/%q then %v/%q", firstStates, firstErr, secondStates, secondErr)
		}
	})
}
