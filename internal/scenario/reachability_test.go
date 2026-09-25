package scenario

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		declared, basis, effective, baseline, want string
	}{
		{DeclaredDeny, BasisPolicy, EffectiveOpen, EffectiveOpen, VerdictBypass},
		{DeclaredDeny, BasisPolicy, EffectiveRefused, EffectiveRefused, VerdictBypass},
		{DeclaredDeny, BasisPolicy, EffectiveTimeout, EffectiveOpen, VerdictMatch},
		{DeclaredAllow, BasisPolicy, EffectiveOpen, EffectiveOpen, VerdictMatch},
		{DeclaredAllow, BasisPolicy, EffectiveTimeout, EffectiveOpen, VerdictOverblock},
		// Dead path (e.g. external -> ClusterIP) says nothing about policy.
		{DeclaredDeny, BasisPolicy, EffectiveTimeout, EffectiveTimeout, VerdictUnreachable},
		{DeclaredMixed, BasisPolicy, EffectiveOpen, EffectiveOpen, VerdictUnknown},
		{DeclaredNA, BasisPolicy, EffectiveOpen, EffectiveOpen, VerdictUnknown},
		// Node-local traffic is allowed by the spec, whatever the policy says.
		{DeclaredDeny, BasisSpecException, EffectiveOpen, EffectiveOpen, VerdictSpecException},
		{DeclaredDeny, BasisSpecException, EffectiveTimeout, EffectiveOpen, VerdictMatch},
		// hostNetwork targets: undefined behaviour, reachable = still a bypass of intent.
		{DeclaredDeny, BasisUndefined, EffectiveOpen, EffectiveOpen, VerdictBypass},
		// SNAT: judged against the intended source; the basis explains it.
		{DeclaredDeny, BasisSNAT, EffectiveOpen, EffectiveOpen, VerdictBypass},
		{DeclaredAllow, BasisSNAT, EffectiveTimeout, EffectiveOpen, VerdictOverblock},
		// One probe can't stand for paths with different bases.
		{DeclaredDeny, BasisMixedPath, EffectiveOpen, EffectiveOpen, VerdictUnknown},
		// REFUSED now but OPEN in baseline: something REJECTed it -> blocked.
		{DeclaredDeny, BasisPolicy, EffectiveRefused, EffectiveOpen, VerdictMatch},
		{DeclaredAllow, BasisPolicy, EffectiveRefused, EffectiveOpen, VerdictOverblock},
		// REFUSED in both: the pod itself answered (nothing listening) -> reached.
		{DeclaredDeny, BasisPolicy, EffectiveRefused, EffectiveRefused, VerdictBypass},
		// error is never reachable
		{DeclaredDeny, BasisPolicy, EffectiveError, EffectiveOpen, VerdictMatch},
	}
	for _, tt := range tests {
		if got := Classify(tt.declared, tt.basis, tt.effective, tt.baseline); got != tt.want {
			t.Errorf("Classify(%s, %s, %s, %s) = %s, want %s",
				tt.declared, tt.basis, tt.effective, tt.baseline, got, tt.want)
		}
	}
}
