package bootstrap

// The host is only a carrier. A received package remains untrusted until
// Reader.Authorize checks its exact hash against the owner's ledger intent.
import (
	"encoding/binary"
	"errors"
	"io"
)

const PackagePort = 9446
const packageMagic = "enclb01\n"

func WritePackage(w io.Writer, id [32]byte, raw []byte) error {
	if zero(id[:]) || len(raw) == 0 || len(raw) > MaxManifestBytes {
		return errors.New("invalid startup package frame")
	}
	b := make([]byte, len(packageMagic)+32+4+len(raw))
	copy(b, packageMagic)
	copy(b[len(packageMagic):], id[:])
	binary.BigEndian.PutUint32(b[len(packageMagic)+32:], uint32(len(raw)))
	copy(b[len(packageMagic)+36:], raw)
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

func ReadPackage(r io.Reader, id [32]byte) ([]byte, error) {
	var header [len(packageMagic) + 36]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, errors.New("truncated startup package header")
	}
	if string(header[:len(packageMagic)]) != packageMagic || string(header[len(packageMagic):len(packageMagic)+32]) != string(id[:]) || zero(id[:]) {
		return nil, errors.New("startup package is not bound to this deployment")
	}
	n := binary.BigEndian.Uint32(header[len(packageMagic)+32:])
	if n == 0 || n > MaxManifestBytes {
		return nil, errors.New("startup package exceeds limit")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, errors.New("truncated startup package")
	}
	var extra [1]byte
	if n, err := r.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, errors.New("startup package has trailing bytes or no end")
	}
	return b, nil
}
