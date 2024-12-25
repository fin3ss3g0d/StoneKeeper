package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

func unpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
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

func AesEncrypt(plainText, encryptedAesKeyHex, xorKeyHex string) (string, error) {
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
}

func AesDecrypt(encryptedBase64, encryptedAesKeyHex, xorKeyHex string) (string, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	decryptedAesKey, err := decryptXorEncryptedAesKey(encryptedAesKeyHex, xorKeyHex)
	if err != nil {
		return "", err
	}
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

	plainBytes = unpad(plainBytes)
	return string(plainBytes), nil
}

func main() {
	aesKey := "fa837efe3b33fd40bd5318b5a6c2431a1e2b6e7e8ecd3709abbb5e4ec7106d4c"
	xorKey := "1bd0ebe60884f5d01fd617a92944571a89a2bebf9508cdb4494c6e7bf4d8a8b3"
	encrypted, err := AesEncrypt("Hello world", aesKey, xorKey)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}
	decrypted, err := AesDecrypt(encrypted, aesKey, xorKey)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return
	}
	fmt.Printf("aesKey: %s xorKey: %s encrypted: %s decrypted: %s\n", aesKey, xorKey, encrypted, decrypted)
}
