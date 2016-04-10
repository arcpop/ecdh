package ecdh_test

import (
    "testing"
    "crypto/elliptic"
    "github.com/arcpop/ecdh"
	"crypto/rand"
)


func TestECDHP224(t *testing.T)  {
    Alice, err := ecdh.GenerateNew(elliptic.P224(), rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    
    Bob, err := ecdh.GenerateNew(elliptic.P224(), rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    
    aliceSecret, err := Alice.GetSharedSecret(Bob.PublicKey)
    if err != nil {
        t.Fatal(err)
    }
    
    bobSecret, err := Bob.GetSharedSecret(Alice.PublicKey)
    if err != nil {
        t.Fatal(err)
    }
    
    if string(bobSecret) != string(aliceSecret) {
        t.Fatal(err)
    }
}

func TestECDHP256(t *testing.T)  {
    Alice, err := ecdh.GenerateNew(elliptic.P256(), rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    
    Bob, err := ecdh.GenerateNew(elliptic.P256(), rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    
    aliceSecret, err := Alice.GetSharedSecret(Bob.PublicKey)
    if err != nil {
        t.Fatal(err)
    }
    
    bobSecret, err := Bob.GetSharedSecret(Alice.PublicKey)
    if err != nil {
        t.Fatal(err)
    }
    
    if string(bobSecret) != string(aliceSecret) {
        t.Fatal(err)
    }
}

func TestECDHP384(t *testing.T)  {
    Alice, err := ecdh.GenerateNew(elliptic.P384(), rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    
    Bob, err := ecdh.GenerateNew(elliptic.P384(), rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    
    aliceSecret, err := Alice.GetSharedSecret(Bob.PublicKey)
    if err != nil {
        t.Fatal(err)
    }
    
    bobSecret, err := Bob.GetSharedSecret(Alice.PublicKey)
    if err != nil {
        t.Fatal(err)
    }
    
    if string(bobSecret) != string(aliceSecret) {
        t.Fatal(err)
    }
}

func TestECDHP521(t *testing.T)  {
    Alice, err := ecdh.GenerateNew(elliptic.P521(), rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    
    Bob, err := ecdh.GenerateNew(elliptic.P521(), rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    
    aliceSecret, err := Alice.GetSharedSecret(Bob.PublicKey)
    if err != nil {
        t.Fatal(err)
    }
    
    bobSecret, err := Bob.GetSharedSecret(Alice.PublicKey)
    if err != nil {
        t.Fatal(err)
    }
    
    if string(bobSecret) != string(aliceSecret) {
        t.Fatal(err)
    }
}