package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

func main() {
	// Replace these with the values from your C++ program's output
	keyHex := "f4c1af2472d6fbe8bc2f12f28926a0f4a3a046755dab2b9faf513f82f5cb342b"
	ivHex := "0e266d1fa0b89a66bf1a210e"
	//keyHex := "30313233343536373839616263646566"
	//ivHex := "313233343536373839306162"
	ciphertextWithTagHex := "9932580449B20D7D39C590A1334D603834EB6CC3A979A0CF2243E6D7A900B8D5491890C5C43C8F932FBDFEBEFDFC8C903568A3CA1F06648A6C55D4"

	// Convert hex strings to byte slices
	key, _ := hex.DecodeString(keyHex)
	fmt.Printf("Key length: %d\n", len(key))
	iv, _ := hex.DecodeString(ivHex)
	fmt.Printf("IV length: %d\n", len(iv))
	ciphertextWithTag, _ := hex.DecodeString(ciphertextWithTagHex)

	// Decrypt the data
	plaintext, err := decryptAESGCM(key, iv, ciphertextWithTag)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted text: %s\n", plaintext)
}

// Decrypt a ciphertext with tag appended at the end
func decryptAESGCM(key, iv, combinedData []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aead.NonceSize()
	if len(iv) != nonceSize {
		return "", fmt.Errorf("invalid nonce size: expected %d, got %d", nonceSize, len(iv))
	}

	// Decrypt the data
	plaintext, err := aead.Open(nil, iv, combinedData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

/*func main() {
	// Example use of the encryption function
	keyHex := "f4c1af2472d6fbe8bc2f12f28926a0f4a3a046755dab2b9faf513f82f5cb342b"
	ivHex := "0e266d1fa0b89a66bf1a210e"
	plaintext := "{\"InternalIP\":\"10.2.0.2\",\"ListenerID\":1,\"Name\":\"DbssCobH4M\",\"ExternalIP\":\"\",\"ID\":0,\"Active\":true,\"Sleep\":10,\"Username\":\"FIN3SS3G0DS-ASU/Dylan\",\"Token\":\"MEDIUM\",\"Hostname\":\"FIN3SS3G0DS-ASU\",\"Time\":\"\",\"OS\":\"Windows 10 Pro 23H2 22631\"}"

	key, _ := hex.DecodeString(keyHex)
	iv, _ := hex.DecodeString(ivHex)

	ciphertextWithTag, err := encryptAESGCM(key, iv, []byte(plaintext))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ciphertext with tag: %s\n", hex.EncodeToString(ciphertextWithTag))
}*/

// encryptAESGCM encrypts data using AES-GCM and returns the ciphertext with the tag appended.
func encryptAESGCM(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, iv, plaintext, nil)
	return ciphertext, nil
}

// Utility function to print a buffer in hex
func printHex(label string, buf []byte) {
	fmt.Printf("%s: %s\n", label, hex.EncodeToString(buf))
}
