package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// Utility function to print a buffer in hex
func printHex(label string, buf []byte) {
	fmt.Printf("%s: %s\n", label, hex.EncodeToString(buf))
}

// xorEncrypt performs Xor encryption on the input byte slice using the given key
func xorEncrypt(input, key []byte) []byte {
	output := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[i]
	}
	return output
}

// decryptXorEncryptedAesKey decrypts an Xor-encrypted Aes key using the given Xor key
func decryptXorEncryptedAesKey(encryptedAesKeyHex, xorKeyHex string) ([]byte, error) {
	var decryptedAesKey []byte
	encryptedAesKey, err := hex.DecodeString(encryptedAesKeyHex)
	if err != nil {
		return decryptedAesKey, err
	}
	xorKey, err := hex.DecodeString(xorKeyHex)
	if err != nil {
		return decryptedAesKey, err
	}

	decryptedAesKey = xorEncrypt(encryptedAesKey, xorKey)
	return decryptedAesKey, nil
}

/*func AesEncrypt(plainText, encryptedAesKeyHex, xorKeyHex string) (string, error) {
	decryptedAesKey, err := decryptXorEncryptedAesKey(encryptedAesKeyHex, xorKeyHex)
	if err != nil {
		return "", err
	}
	keyHash := sha256.Sum256(decryptedAesKey)
	keyBytes := keyHash[:]

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		fmt.Println("Aes NewCipher Error:", err)
		return "", err
	}

	plainBytes := pad([]byte(plainText))

	iv := make([]byte, aes.BlockSize)

	cipherBytes := make([]byte, len(plainBytes))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherBytes, plainBytes)

	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}*/

func AesEncrypt(plaintext, encryptedAesKeyHex, xorKeyHex, ivHex string) (string, error) {
	decryptedAesKey, err := decryptXorEncryptedAesKey(encryptedAesKeyHex, xorKeyHex)
	if err != nil {
		return "", err
	}

	iv, _ := hex.DecodeString(ivHex)

	block, err := aes.NewCipher(decryptedAesKey)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nil, iv, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

/*func AesDecrypt(encryptedBase64, encryptedAesKeyHex, xorKeyHex string) (string, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	fmt.Printf("Decoded base64 hex: ")
	for _, byte := range encryptedBytes {
		fmt.Printf("%02x", byte)
	}
	fmt.Println()

	decryptedAesKey, err := decryptXorEncryptedAesKey(encryptedAesKeyHex, xorKeyHex)
	if err != nil {
		return "", err
	}

	fmt.Printf("Decrypted AES key: ")
	for _, byte := range decryptedAesKey {
		fmt.Printf("%02x", byte)
	}
	fmt.Println()

	keyHash := sha256.Sum256(decryptedAesKey)
	keyBytes := keyHash[:]

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)

	plainBytes := make([]byte, len(encryptedBytes))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plainBytes, encryptedBytes)

	plainBytes, err = unpad(plainBytes)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}*/

// Decrypt a ciphertext with tag appended at the end
func AesDecrypt(encryptedBase64, encryptedAesKeyHex, xorKeyHex, ivHex string) (string, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	//printHex("Decoded base64 hex", encryptedBytes)

	decryptedAesKey, err := decryptXorEncryptedAesKey(encryptedAesKeyHex, xorKeyHex)
	if err != nil {
		return "", err
	}

	//printHex("Decrypted AES key", decryptedAesKey)

	iv, _ := hex.DecodeString(ivHex)

	//printHex("IV", iv)

	block, err := aes.NewCipher(decryptedAesKey)
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
	plaintext, err := aead.Open(nil, iv, encryptedBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
