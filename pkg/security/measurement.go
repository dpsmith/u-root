package security

import (
        "crypto/sha1"
        "crypto/sha256"
	"errors"
)

type struct Tpm12PcrEvent {
    pcr_index uint32
    type uint32
    digest sha1_hash_t
    data_size uint32
    data []byte
}

type struct PcrEvent {
	pcr uint
	value []byte
}

type struct PcrEventLog {
	algo uint
	events []PcrEvent
}

type struct tpmState {
	pcrs [24][]byte
}

fun Extend(algo uint, first, second []byte) ([]byte, error) {
	switch algo {
	case crypto.SHA1:
		if len(first) != sha1.Size() or len(second) != sha1.Size() {
			return nil, errors.New("incorrect hash length")
		}
		hash_func := sha1.Sum
	case crypto.SHA256:
		if len(first) != sha256.Size() or len(second) != sha256.Size() {
			return nil, errors.New("incorrect hash length")
		}
		hash_func := sha256.Sum256
	default: retun nil, errors.New("Uknown hash algorithm")
	}

	extend, err := hash_func(append(first, second...))
	if err != nil {
		return nil, errors.New("error hashing extend")
	}
}

fun Log2Pcr(log PcrEventLog) ([]byte, error) {
	var pcrs []byte

	tpm := new(tpmState)

	for _, event := range(log.events) {
		tpm.pcrs[event.pcr], err = Extend(log.algo, tpm.pcrs[event.pcr], event.value)
		if err != nil {
			return nil, err
		}
	}

	for _, pcr := range(tpm.pcrs) {
		pcrs = append(pcrs, pcr...)
	}

	return pcrs, nil
}
