package cryptoconditions

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestConditionUri(t *testing.T) {
	var err error
	var cond *Condition

	// Test that a valid URI is parsed correctly.

	c, err := ParseUri("cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	cond, ok := c.(*Condition)
	if ok == false {
		t.Fatal("Typecast failed.")
	}
	if cond.Type != CTPreimageSha256 {
		t.Errorf("Wrong type parsed: %v", cond.Type)
	}
	if cond.Features != 3 {
		t.Errorf("Wrong feature flags parsed: %v", cond.Features)
	}
	if !bytes.Equal(cond.Fingerprint, unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")) {
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
	//c, err = ParseUri("cf:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	//if err == nil {
	//	t.Error("Should reject a condition with invalid prefix cf:")
	//}
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

func TestFulfillmentUri(t *testing.T) {
	var err error
	var ff Fulfillment
	var ok bool

	// Test that a valid URIs are parsed correctly.

	// successfully parses the minimal fulfillment
	f, err := ParseUri("cf:0:")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	ff, ok = f.(Fulfillment)
	if ok == false {
		t.Fatal("Typecast failed.")
	}
	pl, err := ff.Payload()
	if err != nil {
		t.Fatal("Error generating (empty) payload.")
	}
	if ff.Type() != CTPreimageSha256 {
		t.Errorf("Wrong ff type: %v", ff.Type())
	}
	if len(pl) != 0 {
		t.Errorf("Payload should be empty: %x", pl)
	}

	// successfully parses a basic fulfillment
	f, err = ParseUri("cf:0:UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	ff, ok = f.(Fulfillment)
	if ok == false {
		t.Fatal("Typecast failed.")
	}
	pl, err = ff.Payload()
	if err != nil {
		t.Fatal("Error generating (empty) payload.")
	}
	if base64.StdEncoding.EncodeToString(pl) != "UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw=" {
		t.Errorf("Incorrect payload: %v", base64.StdEncoding.EncodeToString(pl))
	}

	// successfully parses a fulfillment with base64url characters
	f, err = ParseUri("cf:0:-u_6")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	ff, ok = f.(Fulfillment)
	if ok == false {
		t.Fatal("Typecast failed.")
	}
	pl, err = ff.Payload()
	if err != nil {
		t.Fatal("Error generating (empty) payload.")
	}
	if base64.StdEncoding.EncodeToString(pl) != "+u/6" {
		t.Errorf("Incorrect payload: %v", base64.StdEncoding.EncodeToString(pl))
	}

	// Test that invalid URIs produce errors.

	f, err = ParseUri("af:0:")
	if err == nil {
		t.Error("Should reject a fulfillment with invalid prefix af:")
	}
	f, err = ParseUri("ce:0:")
	if err == nil {
		t.Error("Should reject a fulfillment with invalid prefix ce:")
	}
	f, err = ParseUri("cf;0:")
	if err == nil {
		t.Error("Should reject a fulfillment with invalid prefix cf;")
	}
	//f, err = ParseUri("with invalid prefix cc:")
	//if err == nil {
	//	t.Error("Should reject a fulfillment with invalid prefix cc:")
	//}
	f, err = ParseUri("cf:0::")
	if err == nil {
		t.Error("Should reject a fulfillment with too many segments")
	}
	f, err = ParseUri("cf:0")
	if err == nil {
		t.Error("Should reject a fulfillment with too few segments")
	}
	f, err = ParseUri("cf:9:")
	if err == nil {
		t.Error("Should reject a fulfillment with an invalid version")
	}
	f, err = ParseUri("cf:0:AAA=")
	if err == nil {
		t.Error("Should reject a fulfillment with base64 padding")
	}
	f, err = ParseUri("cf:0:+u/6")
	if err == nil {
		t.Error("Should reject a fulfillment with regular base64 characters")
	}
	f, err = ParseUri("cf:0:Abc.")
	if err == nil {
		t.Error("Should reject a fulfillment with invalid characters")
	}
	f, err = ParseUri("cf:0: AAAA")
	if err == nil {
		t.Error("Should reject a fulfillment containing a space 1")
	}
	f, err = ParseUri("cf:0:AAAA ")
	if err == nil {
		t.Error("Should reject a fulfillment containing a space 2")
	}
	f, err = ParseUri(" cf:0:AAAA")
	if err == nil {
		t.Error("Should reject a fulfillment containing a space 3")
	}
}
