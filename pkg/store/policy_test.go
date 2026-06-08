package store

import (
	"context"
	"errors"
	"testing"
)

func TestSQLiteStore_PolicyCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Missing tenant => not found, no error.
	if _, ok, err := s.GetPolicyYAML(ctx, "acme"); ok || err != nil {
		t.Fatalf("GetPolicyYAML(absent) = ok=%v err=%v, want false,nil", ok, err)
	}

	// Put + Get round-trip.
	doc := []byte("version: \"1\"\nname: acme\n")
	if err := s.PutPolicy(ctx, "acme", doc); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	got, ok, err := s.GetPolicyYAML(ctx, "acme")
	if err != nil || !ok || string(got) != string(doc) {
		t.Fatalf("GetPolicyYAML = %q ok=%v err=%v, want %q,true,nil", got, ok, err, doc)
	}

	// Update in place.
	doc2 := []byte("version: \"1\"\nname: acme-v2\n")
	if err := s.PutPolicy(ctx, "acme", doc2); err != nil {
		t.Fatalf("PutPolicy update: %v", err)
	}
	if got, _, _ := s.GetPolicyYAML(ctx, "acme"); string(got) != string(doc2) {
		t.Errorf("update not applied: got %q", got)
	}

	// List.
	_ = s.PutPolicy(ctx, "globex", []byte("version: \"1\"\nname: globex\n"))
	tenants, err := s.ListPolicyTenants(ctx)
	if err != nil {
		t.Fatalf("ListPolicyTenants: %v", err)
	}
	if len(tenants) != 2 || tenants[0] != "acme" || tenants[1] != "globex" {
		t.Errorf("ListPolicyTenants = %v, want [acme globex] (sorted)", tenants)
	}

	// Delete.
	ok, err = s.DeletePolicy(ctx, "acme")
	if err != nil || !ok {
		t.Fatalf("DeletePolicy = ok=%v err=%v, want true,nil", ok, err)
	}
	if _, ok, _ := s.GetPolicyYAML(ctx, "acme"); ok {
		t.Error("policy still present after delete")
	}
	if ok, _ := s.DeletePolicy(ctx, "acme"); ok {
		t.Error("second delete should report ok=false")
	}

	// Zero-trust.
	if err := s.PutPolicy(ctx, "", doc); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("PutPolicy empty tenant = %v, want ErrTenantRequired", err)
	}
	if _, _, err := s.GetPolicyYAML(ctx, ""); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("GetPolicyYAML empty tenant = %v, want ErrTenantRequired", err)
	}
}
