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

type readResult struct {
	Allowed bool `json:"allowed"`
	Record  json.RawMessage `json:"record"`
	Error   string `json:"error"`
}

func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func connect() (*fabricgw.Gateway, *fabricgw.Network) {
	identity := os.Getenv("ZT_IDENTITY")
	if identity == "" {
		identity = "appAdmin"
	}

	gatewayDir, err := filepath.Abs(".")
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

func readRecord(network *fabricgw.Network, id string) (bool, string, error) {
	svc := &zkp.ZKPService{}
	if err := svc.Setup(); err != nil {
		return false, "", err
	}
	proof, err := svc.ProveAgeRange(35, 18, 120)
	if err != nil {
		return false, "", err
	}

	payload, err := network.GetContract("health").SubmitTransaction("ReadHealthRecord", id, proof.ProofHash)
	if err != nil {
		return false, "", err
	}

	var result readResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return false, "", fmt.Errorf("invalid ReadHealthRecord response: %w", err)
	}
	if result.Error != "" {
		return result.Allowed, result.Error, nil
	}
	return result.Allowed, "", nil
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

		allowed, reason, err := readRecord(network, id)
		if err != nil {
			fmt.Printf("RESULT=DENY\nIDENTITY=%s\nERROR=%v\n", identity, err)
			return
		}
		if !allowed {
			fmt.Printf("RESULT=DENY\nIDENTITY=%s\n", identity)
			if reason != "" {
				fmt.Printf("ERROR=%s\n", reason)
			}
			return
		}
		fmt.Printf("RESULT=ALLOW\nIDENTITY=%s\n\n", identity)
	default:
		log.Fatalf("unknown mode %s", mode)
	}
}

// Keep the JSON dependency explicit for the experiment response decoder.
var _ = json.Valid
