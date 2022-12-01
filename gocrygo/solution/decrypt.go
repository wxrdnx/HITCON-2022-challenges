// 0x200160
// -0x120

package main

import (
    "os"
    "crypto/des"
    "crypto/cipher"
)

var key []byte;

func decrypt(src string, dest string) {
    encrypted, _ := os.ReadFile(src)

    iv := encrypted[:des.BlockSize]
    ciphertext := encrypted[des.BlockSize:]
    block, _ := des.NewTripleDESCipher(key)

    plaintext := make([]byte, len(ciphertext))
    stream := cipher.NewCTR(block, iv)
    stream.XORKeyStream(plaintext, ciphertext)

    f, _ := os.Create(dest)
    defer f.Close()
    f.Write(plaintext)
}

func main() {
    key = []byte {
        0xb3, 0x89, 0xae, 0x52, 0x8f, 0x9a, 0x34, 0xbd,
        0x98, 0x35, 0x59, 0x9b, 0x97, 0x66, 0x85, 0x1b,
        0x82, 0xb4, 0x25, 0x80, 0xb7, 0x20, 0xa3, 0x18,
    }

    decrypt("gocrygo_victim_directory/Desktop/flаg.txt.qq", "flag1.txt")
    decrypt("gocrygo_victim_directory/Pictures/rickroll.jpg.qq", "flag2.jpg")
}
