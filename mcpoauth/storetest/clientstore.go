package storetest

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/i2bskn/authlume/mcpoauth"
)

// RunClientStore checks the contract of mcpoauth.ClientStore against the
// empty store that newStore returns. It calls newStore once per subtest.
// Every time it passes is a whole second in UTC.
func RunClientStore(t *testing.T, newStore func(t *testing.T) mcpoauth.ClientStore) {
	for _, tc := range []struct {
		name string
		run  func(*testing.T, mcpoauth.ClientStore)
	}{
		{"registration round trip", registrationRoundTrip},
		{"registration collision", registrationCollision},
		{"missing registration", registrationMissing},
		{"registration expiry", registrationExpiry},
		{"registration without expiry", registrationForever},
		{"activation", registrationActivate},
		{"activation after expiry", registrationActivateExpired},
		{"concurrent activation", registrationActivateConcurrent},
		{"canceled context", registrationCanceled},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newStore(t)) })
	}
}

// registration n is created at second 0 and expires at second 600.
func registration(n int) mcpoauth.Registration {
	return mcpoauth.Registration{
		ID: "registration-" + string(rune('a'+n)), Name: "Client",
		RedirectURIs: []string{"https://client.example/z", "http://127.0.0.1/callback", "https://client.example/a"},
		CreatedAt:    at(0), ExpiresAt: at(600),
	}
}

func sameRegistration(t *testing.T, got, want mcpoauth.Registration) {
	t.Helper()
	if got.ID != want.ID || got.Name != want.Name || !reflect.DeepEqual(got.RedirectURIs, want.RedirectURIs) ||
		!got.CreatedAt.Equal(want.CreatedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("registration %+v, want %+v", got, want)
	}
}

func registrationRoundTrip(t *testing.T, s mcpoauth.ClientStore) {
	ctx := t.Context()
	reg := registration(0)
	if err := s.CreateClient(ctx, reg); err != nil {
		t.Fatal(err)
	}
	reg.RedirectURIs[0] = "https://changed.example/cb"
	got, err := s.Client(ctx, reg.ID, at(1))
	if err != nil {
		t.Fatal(err)
	}
	sameRegistration(t, got, registration(0))
	got.RedirectURIs[0] = "https://changed.example/cb"
	again, err := s.Client(ctx, reg.ID, at(1))
	if err != nil {
		t.Fatal(err)
	}
	sameRegistration(t, again, registration(0))
}

func registrationCollision(t *testing.T, s mcpoauth.ClientStore) {
	ctx := t.Context()
	if err := s.CreateClient(ctx, registration(0)); err != nil {
		t.Fatal(err)
	}
	other := registration(0)
	other.Name = "Other"
	if err := s.CreateClient(ctx, other); !errors.Is(err, mcpoauth.ErrCollision) {
		t.Fatalf("collision: %v", err)
	}
	got, err := s.Client(ctx, other.ID, at(1))
	if err != nil {
		t.Fatal(err)
	}
	sameRegistration(t, got, registration(0))
}

func registrationMissing(t *testing.T, s mcpoauth.ClientStore) {
	ctx := t.Context()
	if _, err := s.Client(ctx, "missing", at(1)); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatalf("client: %v", err)
	}
	if err := s.Activate(ctx, "missing", at(1)); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatalf("activate: %v", err)
	}
}

func registrationExpiry(t *testing.T, s mcpoauth.ClientStore) {
	ctx := t.Context()
	reg := registration(0)
	if err := s.CreateClient(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Client(ctx, reg.ID, at(599)); err != nil {
		t.Fatalf("before the deadline: %v", err)
	}
	if _, err := s.Client(ctx, reg.ID, at(600)); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatalf("at the deadline: %v", err)
	}
}

func registrationForever(t *testing.T, s mcpoauth.ClientStore) {
	ctx := t.Context()
	reg := registration(0)
	reg.ExpiresAt = time.Time{}
	if err := s.CreateClient(ctx, reg); err != nil {
		t.Fatal(err)
	}
	got, err := s.Client(ctx, reg.ID, at(1_000_000))
	if err != nil {
		t.Fatal(err)
	}
	sameRegistration(t, got, reg)
}

func registrationActivate(t *testing.T, s mcpoauth.ClientStore) {
	ctx := t.Context()
	reg := registration(0)
	if err := s.CreateClient(ctx, reg); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Activate(ctx, reg.ID, at(599)); err != nil {
			t.Fatalf("activate: %v", err)
		}
	}
	got, err := s.Client(ctx, reg.ID, at(1_000_000))
	if err != nil {
		t.Fatalf("after activation: %v", err)
	}
	reg.ExpiresAt = time.Time{}
	sameRegistration(t, got, reg)
	if err := s.Activate(ctx, reg.ID, at(1_000_000)); err != nil {
		t.Fatalf("activate again: %v", err)
	}
}

func registrationActivateExpired(t *testing.T, s mcpoauth.ClientStore) {
	ctx := t.Context()
	reg := registration(0)
	if err := s.CreateClient(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(ctx, reg.ID, at(600)); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatalf("activate at the deadline: %v", err)
	}
	if _, err := s.Client(ctx, reg.ID, at(599)); err != nil {
		t.Fatalf("a refused activation changed the registration: %v", err)
	}
	if _, err := s.Client(ctx, reg.ID, at(600)); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatalf("a refused activation cleared the deadline: %v", err)
	}
}

func registrationActivateConcurrent(t *testing.T, s mcpoauth.ClientStore) {
	ctx := t.Context()
	reg := registration(0)
	if err := s.CreateClient(ctx, reg); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- s.Activate(ctx, reg.ID, at(1)) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent activation: %v", err)
		}
	}
	if _, err := s.Client(ctx, reg.ID, at(1_000_000)); err != nil {
		t.Fatal(err)
	}
}

func registrationCanceled(t *testing.T, s mcpoauth.ClientStore) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	reg := registration(0)
	if err := s.CreateClient(ctx, reg); !errors.Is(err, context.Canceled) {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Client(t.Context(), reg.ID, at(1)); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatalf("a canceled create stored the registration: %v", err)
	}
	if err := s.CreateClient(t.Context(), reg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Client(ctx, reg.ID, at(1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("client: %v", err)
	}
	if err := s.Activate(ctx, reg.ID, at(1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("activate: %v", err)
	}
	if _, err := s.Client(t.Context(), reg.ID, at(600)); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatalf("a canceled activation cleared the deadline: %v", err)
	}
}
