package main

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm"
)

const (
	tpmDevice  string = "/dev/tpm0"
	SecurityPath string = "/sys/kernel/security"
	BinaryBiosPath string = "/sys/kernel/security/tpm0/binary_bios_measurements"
	AsciiBiosPath string = "/sys/kernel/security/tpm0/ascii_bios_measurements"
)

type Attestation struct {
	aik []byte
	nonce []byte
	board_id []byte
	bios_id []byte
	log []byte
	pcrs []byte
	sig []byte
}

func printAttestation(a Attestation) {
	fmt.Printf("AIK Pub:")
	for i, v := range a.aik {
		if i % 40 == 0 {
			fmt.Printf("\n\t")
		}
		fmt.Printf("%02x", v)
	}
	fmt.Printf("\n\n")
	fmt.Printf("Nonce: \n\t%02x\n\n", a.nonce)
	fmt.Printf("Board Identity:\n\t%02x\n\n", a.board_id)
	fmt.Printf("Bios Identity:\n\t%v\n\n", string(a.bios_id))
	fmt.Printf("Bios Measurements:\n\t%v\n\n", string(a.log))
	fmt.Printf("Signing PCR Values:")
	for i, v := range a.pcrs {
		if i == 0 || i % 20 == 0 {
			fmt.Printf("\n\t")
		}
		fmt.Printf("%02x", v)
	}
	fmt.Printf("\n\n")
	fmt.Printf("Signature:")
	for i, v := range a.sig {
		if i % 20 == 0 {
			fmt.Printf("\n\t")
		}
		fmt.Printf("%02x", v)
	}
	fmt.Printf("\n")
}

func tpmOwned() bool {
	f, err := os.Open("/sys/class/tpm/tpm0/device/owned")
        if err != nil {
                return false
        }
        defer f.Close()

	value := make([]byte, 1)
	_, err = f.Read(value)
        if err != nil {
                return false
        }
	if value[0] == '0' {
		return false
	}

	return true
}

func readBiosInfo() ([]byte, error) {
	biosdmi := []string{"/sys/class/dmi/id/bios_date",
			"/sys/class/dmi/id/bios_vendor",
			"/sys/class/dmi/id/bios_version"}
	biosbytes := []byte{}

	for i, p := range biosdmi {
		if f, err := os.Open(p); err != nil {
			return nil, err
		} else {
			defer f.Close()
			b := make([]byte, 255)
			if n, err := f.Read(b); err != nil {
				return nil, err
			} else {
				b = b[:n-1]
			}

			if i != 0 {
				biosbytes = append(biosbytes, []byte{32,45,32}...)
			}
			biosbytes = append(biosbytes, b...)
		}
	}

	return biosbytes, nil
}

func readBoardId() ([]byte, error) {
	boardbytes := []byte{}

	if f, err := os.Open("/sys/class/dmi/id/board_serial"); err != nil {
		return nil, err
	} else {
		defer f.Close()
		b := make([]byte, 40)
		if _, err := f.Read(b); err != nil {
			return nil, err
		}

		boardbytes = append(boardbytes, b...)
	}

	return boardbytes, nil
}

func readAsciiLog() ([]string, error) {
	asciilog := []string{}

	f, err := os.Open(AsciiBiosPath)
        if err != nil {
                return nil, err
        }
        defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if strings.Compare("0", fields[0]) == 0 {
			asciilog = append(asciilog, line)
		}
	}

	return asciilog, scanner.Err()
}

func prompt(msg string) string {
	var input string

	fmt.Printf("%s: ", msg)
	fmt.Scanf("%s", &input)

	return input
}

func main() {
	var attest Attestation

	ownAuth := sha1.Sum([]byte(prompt("Please enter Owner Passphrase")))
	srkAuth := sha1.Sum([]byte(prompt("Please enter SRK Passphrase")))
	aikAuth := sha1.Sum([]byte(prompt("Please enter Signing Passphrase")))
	
	tpmh, err := tpm.OpenTPM(tpmDevice)
	if err != nil {
		log.Fatalf("failed opening tpm: %s", tpmDevice)
	}
	defer tpmh.Close()

	if ! tpmOwned() {
		pubEK, err := tpm.ReadPubEK(tpmh)

		err = tpm.TakeOwnership(tpmh, ownAuth, srkAuth, pubEK)
		if err != nil {
			log.Fatalf("failed taking ownership: %s", tpmDevice)
		}
	}
	
	// In the simplest case, we pass in nil for the Privacy CA key and the
	// label.
	attest.aik, err = tpm.MakeIdentity(tpmh, srkAuth[:], ownAuth[:], aikAuth[:], nil, nil)
	if err != nil {
		log.Fatalf("Unable to generate AIK:", err)
	}

	keyh, err := tpm.LoadKey2(tpmh, attest.aik, srkAuth[:])
	if err != nil {
		log.Fatalf("Unable to load AIK into the TPM:", err)
	}
	defer tpm.CloseKey(tpmh, keyh)

	attest.nonce, err = tpm.GetRandom(tpmh, 20)

	attest.bios_id, err = readBiosInfo()
	attest.board_id, err = readBoardId()

	asciilog, err := readAsciiLog()
	for _, s := range asciilog {
		attest.log = append(attest.log, []byte(s)...)
	}

	blob := append(attest.nonce, attest.board_id...)
	blob = append(blob, attest.bios_id...)
	blob = append(blob, attest.log...)
	pcrs := []int{ 0, 1, 2, 3, 4 }

	attest.sig, attest.pcrs, err = tpm.Quote(tpmh, keyh, blob, pcrs, aikAuth[:])

	printAttestation(attest)
}
