package ecdh

import (
	"crypto/elliptic"
	"errors"
	"io"
)


var ErrPointNotOnCurve = errors.New("The specified public key contains a point which isn't on the curve.")

type ECDH struct {
    Curve elliptic.Curve
    PublicKey []byte
    PrivateKey []byte
}

func GenerateNew(curve elliptic.Curve, randomData io.Reader) (*ECDH, error)  {
    ecdh := &ECDH{ Curve: curve }
    priv, x, y, err := elliptic.GenerateKey(curve, randomData)
    if err != nil {
        return nil, err
    }
    ecdh.PrivateKey = priv
    ecdh.PublicKey = elliptic.Marshal(curve, x, y)
    return ecdh, nil
}

func (ecdh *ECDH) GetSharedSecret(otherPub []byte) ([]byte, error)  {
    pk := otherPub
    px, py := elliptic.Unmarshal(ecdh.Curve, pk)
    if px == nil {
        return nil, ErrPointNotOnCurve
    }
    
    sx, sy := ecdh.Curve.ScalarMult(px, py, ecdh.PrivateKey)
    
    return elliptic.Marshal(ecdh.Curve, sx, sy), nil
}

