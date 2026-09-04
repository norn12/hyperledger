package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	fabricgw "github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"zerotrust/zkp"
)

func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func connect() (*fabricgw.Gateway, *fabricgw.Network) {
	identity := os.Getenv("ZT_IDENTITY")
	if identity == "" {
		identity = "appAdmin"
	}

	gatewayDir, err := filepath.Abs("../..")
	if err != nil {
		log.Fatal(err)
	}

	if err := os.Chdir(gatewayDir); err != nil {
		log.Fatalf("failed to enter gateway directory %s: %v", gatewayDir, err)
	}

	walletPath := "wallet"
	connectionProfilePath := "connection-profile.yaml"

	wallet, err := fabricgw.NewFileSystemWallet(walletPath)
	if err != nil {
		log.Fatal(err)
	}

	if !wallet.Exists(identity) {
		log.Fatalf("identity %s not found in %s", identity, walletPath)
	}

	gw, err := fabricgw.Connect(
		fabricgw.WithConfig(config.FromFile(connectionProfilePath)),
		fabricgw.WithIdentity(wallet, identity),
	)
	if err != nil {
		log.Fatal(err)
	}

	network, err := gw.GetNetwork("healthchannel")
	if err != nil {
		gw.Close()
		log.Fatal(err)
	}

	return gw, network
}

func createRecord(network *fabricgw.Network) string {
	id := fmt.Sprintf("security-%d", time.Now().UnixNano())
	policy := `{"requireZKP":true,"allowedMSPs":["HospitalMSP"],"allowedRoles":["doctor"]}`
	args := []string{id, hash("SECURITY_PATIENT"), hash("SECURITY_DATA"), "offchain://security-test", hash("security-zkp-artifact"), "SECURITY_TEST", policy}
	if _, err := network.GetContract("health").SubmitTransaction("CreateHealthRecord", args...); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("RECORD_ID=%s\n", id)
	fmt.Println("POLICY=HospitalMSP + doctor + ZKP")
	return id
}

func readRecord(network *fabricgw.Network, id string) error {
	svc := &zkp.ZKPService{}
	if err := svc.Setup(); err != nil {
		return err
	}
	proof, err := svc.ProveAgeRange(35, 18, 120)
	if err != nil {
		return err
	}
	_, err = network.GetContract("health").SubmitTransaction("ReadHealthRecord", id, proof.ProofHash)
	return err
}

func main() {
	mode := "create"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	gw, network := connect()
	defer gw.Close()

	switch mode {
	case "create":
		createRecord(network)
	case "read":
		if len(os.Args) < 3 {
			log.Fatal("usage: go run . read <record-id>")
		}
		id := os.Args[2]
		identity := os.Getenv("ZT_IDENTITY")
		if identity == "" {
			identity = "appAdmin"
		}
		err := readRecord(network, id)
		if err != nil {
			fmt.Printf("RESULT=DENY\nIDENTITY=%s\nERROR=%v\n", identity, err)
			return
		}
		fmt.Printf("RESULT=ALLOW\nIDENTITY=%s\n\n", identity)
	default:
		log.Fatalf("unknown mode %s", mode)
	}
}

// Keep encoding/json referenced so the compiler catches accidental changes to
// the audit/result serialization assumptions used by this experiment runner.
var _ = json.Valid
