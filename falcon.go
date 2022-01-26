// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

// Package falcon implements a deterministic variant of the Falcon
// signature scheme.
package falcon

// #cgo CFLAGS: -O3
// #include "falcon.h"
// #include "deterministic.h"
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	// PublicKeySize is the size of a Falcon public key.
	PublicKeySize = C.FALCON_DET1024_PUBKEY_SIZE
	// PrivateKeySize is the size of a Falcon private key.
	PrivateKeySize = C.FALCON_DET1024_PRIVKEY_SIZE
	// CurrentSaltVersion is the salt version number used to compute signatures.
	// The salt version is incremented when the signing procedure changes (rarely).
	CurrentSaltVersion = C.FALCON_DET1024_CURRENT_SALT_VERSION
)

type PublicKey []byte
type PrivateKey []byte

// CompressedSignature is a deterministic Falcon signature in compressed
// form, which is variable-length.
type CompressedSignature []byte

// CTSignature is a deterministic Falcon signature in constant-time form,
// which is fixed-length.
type CTSignature []byte

// GenerateKey generates a public/private key pair from the given seed.
func GenerateKey(seed []byte) (PublicKey, PrivateKey, error) {
	var rng C.shake256_context
	C.shake256_init_prng_from_seed(&rng, unsafe.Pointer(&seed[0]), C.size_t(len(seed)))

	publicKey := make([]byte, PublicKeySize)
	privateKey := make([]byte, PrivateKeySize)

	r := C.falcon_det1024_keygen(&rng, unsafe.Pointer(&privateKey[0]), unsafe.Pointer(&publicKey[0]))
	if r != 0 {
		return nil, nil, fmt.Errorf("falcon keygen failed: %d", int(r))
	}

	return publicKey, privateKey, nil
}

// SignCompressed signs the message with privateKey and returns a compressed
// signature, or an error if signing fails (e.g., due to a malformed private key).
func SignCompressed(privateKey PrivateKey, msg []byte) (CompressedSignature, error) {
	data := C.NULL
	if len(msg) > 0 {
		data = unsafe.Pointer(&msg[0])
	}
	var sigLen C.size_t
	sig := make([]byte, C.FALCON_DET1024_SIG_COMPRESSED_MAXSIZE)
	r := C.falcon_det1024_sign_compressed(unsafe.Pointer(&sig[0]), &sigLen, unsafe.Pointer(&privateKey[0]), data, C.size_t(len(msg)))
	if r != 0 {
		return nil, fmt.Errorf("falcon sign failed: %d", int(r))
	}
	sig = sig[:sigLen]
	return sig, nil
}

// ConvertToCT converts a compressed signature to a CT signature.
func (sig CompressedSignature) ConvertToCT() (CTSignature, error) {
	sigCT := make([]byte, C.FALCON_DET1024_SIG_CT_SIZE)
	r := C.falcon_det1024_convert_compressed_to_ct(unsafe.Pointer(&sigCT[0]), unsafe.Pointer(&sig[0]), C.size_t(len(sig)))
	if r != 0 {
		return nil, fmt.Errorf("falcon convert failed: %d", int(r))
	}
	return sigCT, nil
}

// Verify reports whether sig is a valid compressed signature of msg under publicKey.
func (sig CompressedSignature) Verify(publicKey PublicKey, msg []byte) bool {
	data := C.NULL
	if len(msg) > 0 {
		data = unsafe.Pointer(&msg[0])
	}
	r := C.falcon_det1024_verify_compressed(unsafe.Pointer(&sig[0]), C.size_t(len(sig)), unsafe.Pointer(&publicKey[0]), data, C.size_t(len(msg)))
	return r == 0
}

// Verify reports whether sig is a valid CT signature of msg under publicKey.
func (sig CTSignature) Verify(publicKey PublicKey, msg []byte) bool {
	data := C.NULL
	if len(msg) > 0 {
		data = unsafe.Pointer(&msg[0])
	}
	r := C.falcon_det1024_verify_ct(unsafe.Pointer(&sig[0]), unsafe.Pointer(&publicKey[0]), data, C.size_t(len(msg)))
	return r == 0
}

// SaltVersion returns the salt version number used in the signature.
// The default salt version is 0, if the signature is too short.
func (sig CompressedSignature) SaltVersion() int {
	if len(sig) < 2 {
		return 0
	}
	return int(sig[1])
}

// SaltVersion returns the salt version number used in the signature.
// The default salt version is 0, if the signature is too short.
func (sig CTSignature) SaltVersion() int {
	if len(sig) < 2 {
		return 0
	}
	return int(sig[1])
}

// N=1024 is the degree of Falcon det1024 polynomials.
const N = 1 << C.FALCON_DET1024_LOGN

// Coefficients unpacks a public key representing a ring element h to its vector
// of polynomial coefficients, i.e.,
//
// h(x) = h[0] + h[1] * x + h[2] * x^2 + ... + h[1023] * x^1023.
//
// Returns an error if pubkey is invalid.
func (pub PublicKey) Coefficients() (h [N]uint16, err error) {
	r := C.falcon_det1024_pubkey_coeffs((*C.uint16_t)(&h[0]), unsafe.Pointer(&pub[0]))
	if r != 0 {
		err = fmt.Errorf("falcon_det1024_pubkey_coeffs failed: %d", r)
	}
	return
}

// S2Coefficients unpacks a signature in CT format to the vector of polynomial
// coefficients of the associated ring element s_2. See Section 3.10 of the
// Falcon specification for details. Returns an error if sig cannot be properly
// unpacked.
func (sig CTSignature) S2Coefficients() (s2 [N]int16, err error) {
	r := C.falcon_det1024_s2_coeffs((*C.int16_t)(&s2[0]), unsafe.Pointer(&sig[0]))
	if r != 0 {
		err = fmt.Errorf("falcon_det1024_s2_coeffs failed: %d", r)
	}
	return
}

// S1Coefficients computes the vector of polynomial coefficients of
// s_1 = c - s_2 * h, given the unpacked values h, c, and s_2.
// See Section 3.10 of the Falcon specification for details. Returns an error if
// the aggregate (s_1,s_2) vector is not short enough to constitute a valid
// signature (for the public key corresponding to h, the hash digest
// corresponding to c, and the signature corresponding to s_2).
func S1Coefficients(h [N]uint16, c [N]uint16, s2 [N]int16) (s1 [N]int16, err error) {
	r := C.falcon_det1024_s1_coeffs((*C.int16_t)(&s1[0]), (*C.uint16_t)(&h[0]), (*C.uint16_t)(&c[0]), (*C.int16_t)(&s2[0]))
	if r != 0 {
		err = fmt.Errorf("falcon_det1024_s1_coeffs failed: %d", r)
	}
	return
}

// HashToPointCoefficients hashes msg using the fixed 40-byte salt specified by
// saltVersion, to a ring element c, represented by its vector of polynomial
// coefficients. See Section 3.7 of the Falcon specification for the details of the
// hashing, and Section 2.3.2-3 of the Deterministic Falcon specification for
// the definition of the fixed salt.
func HashToPointCoefficients(msg []byte, saltVersion uint8) (c [N]uint16) {
	data := C.NULL
	if len(msg) > 0 {
		data = unsafe.Pointer(&msg[0])
	}
	C.falcon_det1024_hash_to_point_coeffs((*C.uint16_t)(&c[0]), data, C.size_t(len(msg)), C.uint8_t(saltVersion))
	return
}
