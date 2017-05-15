package mocks

import (
	"hash"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/stretchr/testify/mock"
)

type BCCSP struct {
	mock.Mock
}

func (*BCCSP) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	panic("implement me")
}

func (*BCCSP) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	panic("implement me")
}

func (m *BCCSP) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	args := m.Called(raw, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(bccsp.Key), args.Error(1)
}

func (*BCCSP) GetKey(ski []byte) (k bccsp.Key, err error) {
	panic("implement me")
}

func (*BCCSP) Hash(msg []byte, opts bccsp.HashOpts) (hash []byte, err error) {
	panic("implement me")
}

func (*BCCSP) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	panic("implement me")
}

func (*BCCSP) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	panic("implement me")
}

func (*BCCSP) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	panic("implement me")
}

func (*BCCSP) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	panic("implement me")
}

func (*BCCSP) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	panic("implement me")
}
