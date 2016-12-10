package cryptoconditions

import (
	"testing"
)

func TestConditionUri(t *testing.T) {

	// Test that a valid URI is parsed correctly.

	c, err := ParseUri("cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err != nil {
		t.Errorf("Parse error: %v", err)
	}
	cond := c.(*Condition)
	if cond.Type != CTPreimageSha256 {
		t.Errorf("Wrong type parsed: %v", cond.Type)
	}
	if cond.Features != 3 {
		t.Errorf("Wrong feature flags parsed: %v", cond.Features)
	}
	if cond.Fingerprint != unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Errorf("Wrong fingerprint parsed: %x", cond.Fingerprint)
	}
	if cond.MaxFulfillmentLength != 0 {
		t.Errorf("Wrong MaxFulfillmentLength parsed: %v", cond.MaxFulfillmentLength)
	}

	// Test that invalid URIs produce errors.

	c, err = ParseUri("ac:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition with invalid prefix af:")
	}
	c, err = ParseUri("ca:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition with invalid prefix ce:")
	}
	c, err = ParseUri("cc;0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition with invalid prefix cc;")
	}
	c, err = ParseUri("cf:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition with invalid prefix cf:")
	}
	c, err = ParseUri("cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0:")
	if err == nil {
		t.Error("Should reject a condition with too many segments")
	}
	c, err = ParseUri("cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU")
	if err == nil {
		t.Error("Should reject a condition with too few segments")
	}
	c, err = ParseUri("cc:9:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition with an invalid version")
	}
	c, err = ParseUri("cc:9:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=:0")
	if err == nil {
		t.Error("Should reject a condition with base64 padding")
	}
	//TODO if this fails, we need to find a base64url lib
	c, err = ParseUri("cc:0:3:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition with regular base64 characters (must be base64url)")
	}
	c, err = ParseUri("cc:0:3:47D.Qpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition with invalid characters")
	}
	c, err = ParseUri(" cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition containing a space 1")
	}
	c, err = ParseUri("cc :0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition containing a space 2")
	}
	c, err = ParseUri("cc: 0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition containing a space 3")
	}
	c, err = ParseUri("cc:0 :3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition containing a space 4")
	}
	c, err = ParseUri("cc:0: 3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition containing a space 5")
	}
	c, err = ParseUri("cc:0:3 :47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition containing a space 6")
	}
	c, err = ParseUri("cc:0:3: 47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition containing a space 7")
	}
	c, err = ParseUri("cc:0:3:47D EQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err == nil {
		t.Error("Should reject a condition containing a space 8")
	}
	c, err = ParseUri("cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU :0")
	if err == nil {
		t.Error("Should reject a condition containing a space 9")
	}
	c, err = ParseUri("cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU: 0")
	if err == nil {
		t.Error("Should reject a condition containing a space 10")
	}
	c, err = ParseUri("cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0 ")
	if err == nil {
		t.Error("Should reject a condition containing a space 11")
	}
}
