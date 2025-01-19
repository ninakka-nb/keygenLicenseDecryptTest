package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keygen-sh/jsonapi-go"
	keygen "github.com/keygen-sh/keygen-go/v3"
	"github.com/rs/zerolog"
)

var (
	LicenseFile []byte
	LicenseKey  = ""
	ClusterID   = ""
	logger      zerolog.Logger
)

type certStruct struct {
	Enc string `json:"enc"`
	Sig string `json:"sig"`
	Alg string `json:"alg"`
}

func publicKeyBytes() ([]byte, error) {
	logger.Debug().Msg("I am here")
	if keygen.PublicKey == "" {
		logger.Debug().Msg("I am here")
		return nil, keygen.ErrPublicKeyMissing
	}
	logger.Debug().Msg("I am here")

	key, err := hex.DecodeString(keygen.PublicKey)
	if err != nil {
		logger.Debug().Msg("I am here")
		return nil, keygen.ErrPublicKeyInvalid
	}
	logger.Debug().Msg("I am here")

	if l := len(key); l != ed25519.PublicKeySize {
		logger.Debug().Msg("I am here")
		return nil, keygen.ErrPublicKeyInvalid
	}
	logger.Debug().Msg("I am here")

	return key, nil
}

func certificate(lic *keygen.MachineFile) (*certStruct, error) {
	logger.Debug().Msg("I am here")
	payload := lic.Certificate

	// Remove header and footer
	payload = strings.TrimPrefix(payload, "-----BEGIN MACHINE FILE-----\n")
	payload = strings.TrimSuffix(payload, "-----END MACHINE FILE-----\n")

	logger.Debug().Msg("I am here")
	// Decode
	dec, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	// Unmarshal
	var cert *certStruct
	if err := json.Unmarshal(dec, &cert); err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	return cert, nil
}

// VerifyMachineFile checks if a license file is genuine.
func VerifyMachineFile(lic *keygen.MachineFile) error {
	logger.Debug().Msg("I am here")
	cert, err := certificate(lic)
	if err != nil {
		logger.Debug().Msg("I am here")
		return err
	}
	logger.Debug().Msg("I am here")

	switch {
	case cert.Alg == "aes-256-gcm+ed25519" || cert.Alg == "base64+ed25519":
		logger.Debug().Msg("I am here")
		publicKey, err := publicKeyBytes()
		if err != nil {
			logger.Debug().Msg("I am here")
			return err
		}
		logger.Debug().Msg("I am here")

		msg := []byte("machine/" + cert.Enc)
		sig, err := base64.StdEncoding.DecodeString(cert.Sig)
		if err != nil {
			logger.Debug().Msg("I am here")
			return keygen.ErrMachineFileNotGenuine
		}
		logger.Debug().Msg("I am here")

		if ok := ed25519.Verify(publicKey, msg, sig); !ok {
			logger.Debug().Msg("I am here")
			return keygen.ErrMachineFileNotGenuine
		}
		logger.Debug().Msg("I am here")

		return nil
	default:
		logger.Debug().Msg("I am here")
		return keygen.ErrMachineFileNotSupported
	}
}

func DecryptCertificate(secret string, cert *certStruct) ([]byte, error) {
	logger.Debug().Msg("I am here")
	parts := strings.SplitN(cert.Enc, ".", 3)

	// Decode parts
	ciphertext, err := base64.StdEncoding.DecodeString(parts[0])
	logger.Debug().Msg("I am here")
	if err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	iv, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	tag, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	// Hash secret
	h := sha256.New()
	h.Write([]byte(secret))

	key := h.Sum(nil)

	// Setup AES
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	aes, err := cipher.NewGCM(block)
	if err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	// Append auth tag to ciphertext
	ciphertext = append(ciphertext, tag...)

	// Decrypt
	plaintext, err := aes.Open(nil, iv, ciphertext, nil)
	if err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	return plaintext, nil
}

// Decrypt decrypts the machine file's encrypted dataset. It returns the decrypted dataset
// and any errors that occurred during decryption, e.g. ErrMachineFileNotEncrypted.
func Decrypt(lic *keygen.MachineFile, key string) (*keygen.MachineFileDataset, error) {
	logger.Debug().Msg("I am here")
	cert, err := certificate(lic)
	if err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	switch {
	case cert.Alg == "aes-256-gcm+rsa-pss-sha256" || cert.Alg == "aes-256-gcm+rsa-sha256":
		logger.Debug().Msg("I am here")
		return nil, keygen.ErrMachineFileNotSupported
	case cert.Alg != "aes-256-gcm+ed25519":
		logger.Debug().Msg("I am here")
		return nil, keygen.ErrMachineFileNotEncrypted
	}
	logger.Debug().Msg("I am here")

	// Decrypt
	data, err := DecryptCertificate(key, cert)
	if err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	// Unmarshal
	dataset := &keygen.MachineFileDataset{}

	if _, err := jsonapi.Unmarshal(data, dataset); err != nil {
		logger.Debug().Msg("I am here")
		return nil, err
	}
	logger.Debug().Msg("I am here")

	if keygen.MaxClockDrift >= 0 && time.Until(dataset.Issued) > keygen.MaxClockDrift {
		logger.Debug().Msg("I am here")
		return dataset, keygen.ErrSystemClockUnsynced
	}

	if dataset.TTL != 0 && time.Now().After(dataset.Expiry) {
		logger.Debug().Msg("I am here")
		return dataset, keygen.ErrMachineFileExpired
	}

	logger.Debug().Msg("I am here")
	return dataset, nil
}

func MyValidateLicense() (bool, error) {
	// Verify the license file's signature
	lic := &keygen.MachineFile{Certificate: string(LicenseFile)}

	err := VerifyMachineFile(lic)
	switch {
	case err == keygen.ErrMachineFileNotGenuine:
		logger.Debug().Msg(fmt.Sprintf("Machine file is not genuine: err=%v", err))
		return false, err
	case err != nil:
		logger.Debug().Msg(fmt.Sprintf("Machine file verification failed: err=%v", err))
		return false, err
	}

	dataset, err := Decrypt(lic, LicenseKey+ClusterID)
	switch {
	case err == keygen.ErrMachineFileExpired:
		logger.Debug().Msg("Machine file is expired!")
		logger.Debug().Msg(fmt.Sprintf("Decrypted dataset: %+v\n", dataset))
		return false, err
	case err != nil:
		logger.Debug().Msg(fmt.Sprintf("Machine file decryption failed: err=%v", err))
		return false, err
	}

	logger.Debug().Msg("Machine file is genuine!")
	logger.Debug().Msg(fmt.Sprintf("Decrypted dataset: %+v\n", dataset))
	return true, nil
}

func main() {
	loglevel := zerolog.DebugLevel

	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}

	zerolog.SetGlobalLevel(loglevel)

	logger = zerolog.New(os.Stdout).Level(loglevel).With().Timestamp().Caller().Logger()

	keygen.PublicKey = "6fa492205ff3234e703a9a5b76740ad263a1989d7840c08254836b61eac0a186"

	var err error
	LicenseFile, err = os.ReadFile("machine.lic")
	if err != nil {
		errMsg := "license file is not specified, or empty"
		logger.Debug().Msg(errMsg)
		return
	}

	LicenseKey = "D8AA77-E53ADB-6009FE-151C2E-560CC0-V3"

	ClusterID = "6cdb99b0-1a72-4af4-b502-47b96df731dd"

	logger.Debug().Msg("Local validation")
	ret, err := MyValidateLicense()
	if err != nil {
		logger.Debug().Msg(fmt.Sprintf("Return value %+v; Error: %+v\n", ret, err.Error()))
	}

	logger.Debug().Msg("Library validation")
	// Verify the license file's signature
	lic := &keygen.MachineFile{Certificate: string(LicenseFile)}

	err = lic.Verify()
	switch {
	case err == keygen.ErrMachineFileNotGenuine:
		logger.Debug().Msg(fmt.Sprintf("Machine file is not genuine: err=%v", err))
		return
	case err != nil:
		logger.Debug().Msg(fmt.Sprintf("Machine file verification failed: err=%v", err))
		return
	}

	dataset, err := lic.Decrypt(LicenseKey + ClusterID)
	switch {
	case err == keygen.ErrMachineFileExpired:
		logger.Debug().Msg("Machine file is expired!")
		logger.Debug().Msg(fmt.Sprintf("Decrypted dataset: %+v\n", dataset))
		return
	case err != nil:
		logger.Debug().Msg(fmt.Sprintf("Machine file decryption failed: err=%v", err))
		return
	}

	logger.Debug().Msg("Machine file is genuine!")
	logger.Debug().Msg(fmt.Sprintf("Decrypted dataset: %+v\n", dataset))
}
