package aesgen

import (
	"crypto/rand"
	"encoding/hex"
	"log"
)

func GenerateKeysAndIV() (string, string, string) {
	length := 32

	aesKey := GenerateRandomAESKey(length)
	iv := GenerateRandomIV()
	xorKey := GenerateRandomXORKey(length)
	encryptedAESKey := xorEncrypt(aesKey, xorKey)

	// Hex-encoded strings
	encryptedAESKeyHex := hex.EncodeToString(encryptedAESKey)
	ivHex := hex.EncodeToString(iv)
	xorKeyHex := hex.EncodeToString(xorKey)

	/*fmt.Printf("Generated AES Key: %s\n", hex.EncodeToString(aesKey))
	fmt.Printf("Generated XOR Key: %s\n", xorKeyHex)
	fmt.Printf("XOR-Encrypted AES Key: %s\n", encryptedAESKeyHex)

	// Decrypt the XOR-Encrypted AES Key
	decryptedAESKeyHex, err := DecryptXOREncryptedAESKey(encryptedAESKeyHex, xorKeyHex)
	if err != nil {
		log.Fatalf("Error during decryption: %v", err)
	}
	fmt.Printf("Decrypted AES Key: %s\n", decryptedAESKeyHex)
	fmt.Printf("%s %s\n", encryptedAESKeyHex, xorKeyHex)*/

	return encryptedAESKeyHex, xorKeyHex, ivHex
}

// GenerateRandomString generates a random string of the given length
func GenerateRandomString(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatalf("Error generating random string: %v", err)
	}
	return hex.EncodeToString(bytes)[:length]
}

// DecryptXOREncryptedAESKey decrypts an XOR-encrypted AES key using the given XOR key
func DecryptXOREncryptedAESKey(encryptedAESKeyHex, xorKeyHex string) (string, error) {
	encryptedAESKey, err := hex.DecodeString(encryptedAESKeyHex)
	if err != nil {
		return "", err
	}
	xorKey, err := hex.DecodeString(xorKeyHex)
	if err != nil {
		return "", err
	}

	decryptedAESKey := xorEncrypt(encryptedAESKey, xorKey)
	return hex.EncodeToString(decryptedAESKey), nil
}

// GenerateRandomAESKey generates a random AES encryption key of the given length
func GenerateRandomAESKey(length int) []byte {
	if length != 16 && length != 24 && length != 32 {
		log.Fatalf("Invalid AES key length: %d. Valid lengths are 16, 24, or 32 bytes.", length)
		return nil
	}

	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Error generating random AES key: %v", err)
	}
	return key
}

func GenerateRandomIV() []byte {
	iv := make([]byte, 12)
	_, err := rand.Read(iv)
	if err != nil {
		log.Fatalf("Error generating random IV: %v", err)
	}
	return iv
}

// GenerateRandomXORKey generates a random XOR key of the same length as the AES key
func GenerateRandomXORKey(length int) []byte {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Error generating random XOR key: %v", err)
	}
	return key
}

// xorEncrypt performs XOR encryption on the input byte slice using the given key
func xorEncrypt(input, key []byte) []byte {
	output := make([]byte, len(input))
	keyLen := len(key)
	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[i%keyLen]
	}
	return output
}
