package gateway

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxIPFSPayloadSize = 16 << 20

type IPFSClient struct {
	APIURL string
	Key    []byte
	HTTP   *http.Client
}

func NewIPFSClientFromEnv() (*IPFSClient, error) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("ZT_IPFS_ENABLED")), "true") {
		return nil, nil
	}
	apiURL := strings.TrimRight(strings.TrimSpace(os.Getenv("ZT_IPFS_API_URL")), "/")
	if apiURL == "" {
		apiURL = "http://127.0.0.1:5001/api/v0"
	}
	keyHex := strings.TrimSpace(os.Getenv("ZT_IPFS_ENCRYPTION_KEY"))
	if keyHex == "" {
		return nil, fmt.Errorf("ZT_IPFS_ENCRYPTION_KEY is required when ZT_IPFS_ENABLED=true")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid ZT_IPFS_ENCRYPTION_KEY: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("ZT_IPFS_ENCRYPTION_KEY must decode to exactly 32 bytes")
	}
	return &IPFSClient{APIURL: apiURL, Key: key, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (c *IPFSClient) EncryptJSON(data []byte) ([]byte, error) {
	if len(data) > maxIPFSPayloadSize {
		return nil, fmt.Errorf("IPFS payload exceeds %d MiB limit", maxIPFSPayloadSize>>20)
	}
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	result := make([]byte, 0, 4+len(nonce)+len(ciphertext))
	result = append(result, []byte("ZTB1")...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result, nil
}

func (c *IPFSClient) DecryptJSON(data []byte) ([]byte, error) {
	if len(data) < 4 || string(data[:4]) != "ZTB1" {
		return nil, fmt.Errorf("invalid encrypted IPFS payload format")
	}
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < 4+nonceSize {
		return nil, fmt.Errorf("encrypted IPFS payload is truncated")
	}
	plaintext, err := gcm.Open(nil, data[4:4+nonceSize], data[4+nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt IPFS payload: %w", err)
	}
	if len(plaintext) > maxIPFSPayloadSize {
		return nil, fmt.Errorf("decrypted IPFS payload exceeds %d MiB limit", maxIPFSPayloadSize>>20)
	}
	return plaintext, nil
}

func (c *IPFSClient) AddEncryptedJSON(data []byte, filename string) (string, error) {
	encrypted, err := c.EncryptJSON(data)
	if err != nil {
		return "", err
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return "", fmt.Errorf("create IPFS multipart field: %w", err)
	}
	if _, err := part.Write(encrypted); err != nil {
		return "", fmt.Errorf("write encrypted IPFS payload: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("close IPFS multipart body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.APIURL+"/add?pin=true&cid-version=1", &body)
	if err != nil {
		return "", fmt.Errorf("create IPFS add request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("IPFS add request failed: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read IPFS add response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("IPFS add returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var result struct {
		Name string `json:"Name"`
		Hash string `json:"Hash"`
		CID  struct {
			String string `json:"/"`
		} `json:"Cid"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return "", fmt.Errorf("parse IPFS add response: %w", err)
	}
	cid := strings.TrimSpace(result.Hash)
	if cid == "" {
		cid = strings.TrimSpace(result.CID.String)
	}
	if cid == "" {
		return "", fmt.Errorf("IPFS add response did not contain a CID")
	}
	return cid, nil
}

func (c *IPFSClient) CatEncrypted(cid string) ([]byte, error) {
	cid = strings.TrimSpace(strings.TrimPrefix(cid, "ipfs://"))
	if cid == "" {
		return nil, fmt.Errorf("empty IPFS CID")
	}
	req, err := http.NewRequest(http.MethodPost, c.APIURL+"/cat?arg="+url.QueryEscape(cid), nil)
	if err != nil {
		return nil, fmt.Errorf("create IPFS cat request: %w", err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("IPFS cat request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("IPFS cat returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	limit := int64(maxIPFSPayloadSize + 129)
	encrypted, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("read IPFS object: %w", err)
	}
	if int64(len(encrypted)) >= limit {
		return nil, fmt.Errorf("encrypted IPFS object exceeds %d MiB limit", maxIPFSPayloadSize>>20)
	}
	return c.DecryptJSON(encrypted)
}
