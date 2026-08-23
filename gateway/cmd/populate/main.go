package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

func main() {
	walletPath := "wallet"
	// Use relative path to avoid breakage on different machines
	absPath, _ := filepath.Abs("..")
	mspPath := filepath.Join(absPath, "crypto-config", "peerOrganizations", "hospital.zerotrust.com", "users", "Admin@hospital.zerotrust.com", "msp")

	// Create wallet
	wallet, err := gateway.NewFileSystemWallet(walletPath)
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	if wallet.Exists("appAdmin") {
		fmt.Println("appAdmin already exists in wallet")
		return
	}

	// Read cert
	certPath := filepath.Join(mspPath, "signcerts", "Admin@hospital.zerotrust.com-cert.pem")
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Fatalf("Failed to read cert: %v", err)
	}

	// Read key
	keyDir := filepath.Join(mspPath, "keystore")
	files, err := ioutil.ReadDir(keyDir)
	if err != nil || len(files) == 0 {
		log.Fatalf("Failed to read keystore: %v", err)
	}
	keyPath := filepath.Join(keyDir, files[0].Name())
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("Failed to read key: %v", err)
	}

	// Create identity
	identity := gateway.NewX509Identity("HospitalMSP", string(cert), string(key))

	// Put into wallet
	err = wallet.Put("appAdmin", identity)
	if err != nil {
		log.Fatalf("Failed to put identity into wallet: %v", err)
	}

	fmt.Println("Successfully populated wallet with appAdmin identity")
}
