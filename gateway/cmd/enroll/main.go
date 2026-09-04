package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

type UserSpec struct {
	Username string
	OrgName  string
	MSPId    string
	Role     string
	Secret   string
}

func main() {
	gatewayDir, err := filepath.Abs(".")
	if err != nil {
		log.Fatalf("failed to get absolute gateway directory: %v", err)
	}

	if err := os.Chdir(gatewayDir); err != nil {
		log.Fatalf("failed to enter gateway directory %s: %v", gatewayDir, err)
	}

	connectionProfilePath := "connection-profile.yaml"
	walletPath := "wallet"

	wallet, err := gateway.NewFileSystemWallet(walletPath)
	if err != nil {
		log.Fatalf("failed to open file system wallet: %v", err)
	}

	sdk, err := fabsdk.New(config.FromFile(connectionProfilePath))
	if err != nil {
		log.Fatalf("failed to create Fabric SDK instance: %v", err)
	}
	defer sdk.Close()

	users := []UserSpec{
		{
			Username: "appAdmin",
			OrgName:  "HospitalOrg",
			MSPId:    "HospitalMSP",
			Role:     "admin",
			Secret:   "appAdminpw",
		},
		{
			Username: "doctor",
			OrgName:  "HospitalOrg",
			MSPId:    "HospitalMSP",
			Role:     "doctor",
			Secret:   "doctorpw",
		},
		{
			Username: "insurer",
			OrgName:  "InsurerOrg",
			MSPId:    "InsurerMSP",
			Role:     "insurer",
			Secret:   "insurerpw",
		},
	}

	for _, u := range users {
		if wallet.Exists(u.Username) {
			fmt.Printf("Identity %s already exists in wallet (%s)\n", u.Username, walletPath)
			continue
		}

		mspClient, err := msp.New(sdk.Context(), msp.WithOrg(u.OrgName))
		if err != nil {
			log.Fatalf("failed to create MSP client for org %s: %v", u.OrgName, err)
		}

		// Ensure CA admin is enrolled for registration authority
		err = mspClient.Enroll("admin", msp.WithSecret("adminpw"))
		if err != nil {
			log.Printf("CA admin enrollment info (%s): %v", u.OrgName, err)
		}

		// Register user as client type with custom role attribute
		req := &msp.RegistrationRequest{
			Name:           u.Username,
			Type:           "client",
			Secret:         u.Secret,
			MaxEnrollments: -1,
			Attributes: []msp.Attribute{
				{
					Name:  "role",
					Value: u.Role,
					ECert: true,
				},
			},
		}

		regSecret, regErr := mspClient.Register(req)
		if regErr != nil {
			log.Printf("Registration note for %s (%v), attempting enrollment with provided secret...", u.Username, regErr)
			regSecret = u.Secret
		}

		// Enroll user certificate
		err = mspClient.Enroll(u.Username, msp.WithSecret(regSecret))
		if err != nil {
			log.Fatalf("failed to enroll identity %s for %s: %v", u.Username, u.OrgName, err)
		}

		signingIdentity, err := mspClient.GetSigningIdentity(u.Username)
		if err != nil {
			log.Fatalf("failed to retrieve signing identity for %s: %v", u.Username, err)
		}

		cert := signingIdentity.EnrollmentCertificate()
		keyBytes, err := signingIdentity.PrivateKey().Bytes()
		if err != nil {
			log.Fatalf("failed to get private key bytes for %s: %v", u.Username, err)
		}

		x509Identity := gateway.NewX509Identity(u.MSPId, string(cert), string(keyBytes))
		if err := wallet.Put(u.Username, x509Identity); err != nil {
			log.Fatalf("failed to import %s into wallet: %v", u.Username, err)
		}

		fmt.Printf("Successfully registered and enrolled %s (%s, role=%s) into wallet\n", u.Username, u.MSPId, u.Role)
	}

	fmt.Println("\nAll experiment identities provisioned successfully.")
}
