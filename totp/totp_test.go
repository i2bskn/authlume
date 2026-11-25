package totp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/i2bskn/authlume/totp"
)

const subject = "app-user-17"

// fixtureStore records the verifier's arguments; concurrency is exercised with
// the example's locking store through its HTTPS login handler.
type fixtureStore struct {
	credential          totp.Credential
	loadErr, consumeErr error
	step                int64
	consumes            int
}

func fixture() *fixtureStore {
	return &fixtureStore{credential: totp.Credential{ID: "activation-7",
		Secret: []byte("12345678901234567890")}, step: -1}
}

func (s *fixtureStore) Load(_ context.Context, who string) (totp.Credential, error) {
	if who != subject {
		return totp.Credential{}, totp.ErrInvalid
	}
	return s.credential, s.loadErr
}

func (s *fixtureStore) Consume(_ context.Context, who, id string, step int64) error {
	s.consumes++
	if s.consumeErr != nil {
		return s.consumeErr
	}
	if who != subject || id != s.credential.ID || step <= s.step {
		return totp.ErrInvalid
	}
	s.step = step
	return nil
}

func verifier(t *testing.T, s *fixtureStore, seconds int64) *totp.Verifier {
	t.Helper()
	v, err := totp.New(s, func() time.Time { return time.Unix(seconds, 0) })
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRFC6238(t *testing.T) {
	// Six-digit suffixes of the SHA-1 vectors in RFC 6238 Appendix B.
	for _, tc := range []struct {
		seconds int64
		code    string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"},
		{1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"},
	} {
		s := fixture()
		v := verifier(t, s, tc.seconds)
		if err := v.Verify(t.Context(), subject, tc.code); err != nil || s.step != tc.seconds/30 {
			t.Errorf("at %d: err=%v step=%d", tc.seconds, err, s.step)
		}
	}
}

func TestAcceptanceWindow(t *testing.T) {
	for _, tc := range []struct {
		seconds int64
		valid   bool
	}{
		{-1, false}, {29, false}, {30, true}, {59, true}, {60, true}, {89, true}, {90, false},
	} {
		s := fixture()
		err := verifier(t, s, tc.seconds).Verify(t.Context(), subject, "287082")
		if tc.valid {
			if err != nil || s.step != 1 {
				t.Errorf("at %d: err=%v step=%d", tc.seconds, err, s.step)
			}
		} else if !errors.Is(err, totp.ErrInvalid) || s.consumes != 0 {
			t.Errorf("at %d: err=%v consumes=%d", tc.seconds, err, s.consumes)
		}
	}
}

func TestCredentialAndConsumption(t *testing.T) {
	s := fixture()
	v := verifier(t, s, 59)
	for _, code := range []string{"", "28708", "2870820", " 87082", "28708a", "000000"} {
		if err := v.Verify(t.Context(), subject, code); !errors.Is(err, totp.ErrInvalid) || s.consumes != 0 {
			t.Fatalf("invalid code: err=%v consumes=%d", err, s.consumes)
		}
	}
	for _, who := range []string{"", "another-subject"} {
		if err := v.Verify(t.Context(), who, "287082"); !errors.Is(err, totp.ErrInvalid) || s.consumes != 0 {
			t.Fatalf("missing subject: err=%v consumes=%d", err, s.consumes)
		}
	}
	if err := v.Verify(t.Context(), subject, "287082"); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(t.Context(), subject, "287082"); !errors.Is(err, totp.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestStoreErrors(t *testing.T) {
	unavailable := errors.New("offline")
	for _, tc := range []struct {
		name     string
		setup    func(*fixtureStore)
		want     error
		consumes int
	}{
		{"lookup", func(s *fixtureStore) { s.loadErr = unavailable }, unavailable, 0},
		{"missing id", func(s *fixtureStore) { s.credential.ID = "" }, totp.ErrRecord, 0},
		{"short secret", func(s *fixtureStore) { s.credential.Secret = make([]byte, 19) }, totp.ErrRecord, 0},
		{"rotated before consume", func(s *fixtureStore) { s.consumeErr = totp.ErrInvalid }, totp.ErrInvalid, 1},
		{"write failure", func(s *fixtureStore) { s.consumeErr = unavailable }, unavailable, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture()
			tc.setup(s)
			err := verifier(t, s, 59).Verify(t.Context(), subject, "287082")
			if !errors.Is(err, tc.want) || s.consumes != tc.consumes {
				t.Errorf("err=%v consumes=%d", err, s.consumes)
			}
		})
	}
}

func TestCanceled(t *testing.T) {
	s := fixture()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := verifier(t, s, 59).Verify(ctx, subject, "287082"); !errors.Is(err, context.Canceled) || s.consumes != 0 {
		t.Fatalf("err=%v consumes=%d", err, s.consumes)
	}
}
