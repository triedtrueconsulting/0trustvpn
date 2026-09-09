package config

import "testing"

// The control plane hashes tokens after upper-casing and stripping "-" and
// " " (hash_token in api/main.py), so it accepts every spelling below. The
// CLI used to refuse all but the first, which locked a customer out of a
// token the server would have taken. Each case is written out rather than
// generated: the interesting inputs here are the ones a random draw of valid
// tokens never produces (bug class #13).
func TestNormalizeTokenAcceptsEverySpellingTheServerDoes(t *testing.T) {
	const want = "ABCD-2345-EFGH-6789"
	for _, in := range []string{
		"ABCD-2345-EFGH-6789", // canonical
		"ABCD2345EFGH6789",    // no separators at all
		"abcd-2345-efgh-6789", // lower case
		"abcd2345efgh6789",    // both
		"AbCd-2345-eFgH-6789", // mixed case
		"ABCD 2345 EFGH 6789", // spaces instead of dashes
		"  ABCD-2345-EFGH-6789  \n",
		"ABCD-2345\tEFGH 6789", // whatever a paste dragged along
		"A B C D 2 3 4 5 E F G H 6 7 8 9",
		"----ABCD2345EFGH6789----", // separators in nonsense places
	} {
		got, ok := NormalizeToken(in)
		if !ok {
			t.Errorf("NormalizeToken(%q) rejected a token the server accepts", in)
			continue
		}
		if got != want {
			t.Errorf("NormalizeToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeTokenRejectsWhatTheServerWouldAlsoReject(t *testing.T) {
	for _, tc := range []struct{ in, why string }{
		{"", "empty"},
		{"ABCD-2345-EFGH-678", "fifteen characters"},
		{"ABCD-2345-EFGH-67899", "seventeen characters"},
		{"ABCD2345EFGH6789A", "seventeen, unseparated"},
		{"ABCD-2345-EFGH-6789-ABCD", "a second token appended"},
		{"IBCD-2345-EFGH-6789", "I is not in the alphabet"},
		{"OBCD-2345-EFGH-6789", "O is not in the alphabet"},
		{"0BCD-2345-EFGH-6789", "0 is not in the alphabet"},
		{"1BCD-2345-EFGH-6789", "1 is not in the alphabet"},
		{"ABCD-2345-EFGH-678!", "punctuation"},
		{"ABCD-2345-EFGH-678é", "non-ASCII"},
		{"----------------", "separators only"},
	} {
		if got, ok := NormalizeToken(tc.in); ok {
			t.Errorf("NormalizeToken(%q) = %q, accepted (%s)", tc.in, got, tc.why)
		}
	}
}

// A token that has been normalized once must survive being normalized again:
// the CLI stores the canonical form and re-reads it on every command.
func TestNormalizeTokenIsIdempotent(t *testing.T) {
	first, ok := NormalizeToken("abcd2345efgh6789")
	if !ok {
		t.Fatal("first pass rejected a valid token")
	}
	second, ok := NormalizeToken(first)
	if !ok || second != first {
		t.Fatalf("second pass gave (%q, %v), want (%q, true)", second, ok, first)
	}
}

// The alphabet has to stay in step with TOKEN_ALPHABET in api/main.py — the
// point of the exclusions is that a token read off a screen cannot be
// mistyped into a *different valid* token.
func TestTokenAlphabetExcludesTheAmbiguousCharacters(t *testing.T) {
	if len(TokenAlphabet) != 32 {
		t.Errorf("alphabet is %d chars, api/main.py has 32", len(TokenAlphabet))
	}
	for _, ch := range "IO01" {
		for _, have := range TokenAlphabet {
			if have == ch {
				t.Errorf("%q is in the alphabet; it is excluded server-side", ch)
			}
		}
	}
}

func TestMaskTokenShowsEnoughToRecognizeAndNotEnoughToUse(t *testing.T) {
	got := MaskToken("ABCD-2345-EFGH-6789")
	if got != "ABCD-****-****-6789" {
		t.Errorf("MaskToken = %q", got)
	}
	// A short or empty value must not panic — it reaches this from state.json,
	// which a customer can edit.
	for _, in := range []string{"", "AB", "ABCD-234"} {
		if MaskToken(in) != in {
			t.Errorf("MaskToken(%q) altered a too-short value", in)
		}
	}
}
