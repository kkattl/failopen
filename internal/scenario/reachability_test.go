package scenario

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		declared, effective, baseline, want string
	}{
		{DeclaredDeny, EffectiveOpen, EffectiveOpen, VerdictBypass},
		{DeclaredDeny, EffectiveRefused, EffectiveRefused, VerdictBypass},
		{DeclaredDeny, EffectiveTimeout, EffectiveOpen, VerdictMatch},
		{DeclaredAllow, EffectiveOpen, EffectiveOpen, VerdictMatch},
		{DeclaredAllow, EffectiveTimeout, EffectiveOpen, VerdictOverblock},
		// Dead path (e.g. external -> ClusterIP) says nothing about policy.
		{DeclaredDeny, EffectiveTimeout, EffectiveTimeout, VerdictUnreachable},
		{DeclaredMixed, EffectiveOpen, EffectiveOpen, VerdictUnknown},
		{DeclaredNA, EffectiveOpen, EffectiveOpen, VerdictUnknown},
	}
	for _, tt := range tests {
		if got := Classify(tt.declared, tt.effective, tt.baseline); got != tt.want {
			t.Errorf("Classify(%s, %s, %s) = %s, want %s",
				tt.declared, tt.effective, tt.baseline, got, tt.want)
		}
	}
}
