package gateway

import (
	"bytes"
	"testing"
)

func TestIPFSClientEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	client := &IPFSClient{Key: key}
	plaintext := []byte(`{"patient":"example","result":"normal"}`)

	encrypted, err := client.EncryptJSON(plaintext)
	if err != nil {
		t.Fatalf("EncryptJSON failed: %v", err)
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted payload must differ from plaintext")
	}

	decrypted, err := client.DecryptJSON(encrypted)
	if err != nil {
		t.Fatalf("DecryptJSON failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestIPFSClientRejectsTamperedPayload(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	client := &IPFSClient{Key: key}
	ciphertext, err := client.EncryptJSON([]byte(`{"secret":true}`))
	if err != nil {
		t.Fatalf("EncryptJSON failed: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0x01
	if _, err := client.DecryptJSON(ciphertext); err == nil {
		t.Fatal("expected tampered payload to fail authentication")
	}
}
