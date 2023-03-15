package main

import (
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/b-sn/x509wrapper"
	"github.com/logrusorgru/aurora"
	"gopkg.in/yaml.v2"
)

const (
	defCAConfigFile   = "./ca.yml"
	defCertConfigFile = "./cert.yml"
	CACertFileName    = ""
)

type CAConf struct {
	Folder             string `yaml:"cert_folder"`
	Country            string
	Organization       string
	OrganizationalUnit string `yaml:"organizational_unit"`
	Locality           string
	Province           string
	StreetAddress      string `yaml:"street_address"`
	PostalCode         string `yaml:"postal_code"`
	DNS                string `yaml:"dns"`
	Name               string `yaml:"name"`
}

var (
	configFile, certFolder string
	createCA, createCert   bool
	certConfigFile         string
)

func main() {
	flag.StringVar(&configFile, "config-file", defCAConfigFile, "CA certificate configuration, required for it creation")
	flag.StringVar(&certFolder, "ca-cert-folder", "", "CA certificates folder")
	flag.BoolVar(&createCA, "create-ca", false, "Need to create CA certificate")
	flag.BoolVar(&createCert, "create-cert", false, "Need to create new certificate")
	flag.StringVar(&certConfigFile, "cert-config", defCertConfigFile, "New certificate name")

	flag.Parse()

	// Get configuration
	var cfg CAConf
	if configFile != "" {
		configFile, err := filepath.Abs(configFile)

		if err != nil {
			Warn(fmt.Sprintf("Configuration file [%s] wrong path, skipped", configFile))

		} else if _, err := os.Stat(configFile); os.IsNotExist(err) {
			Warn(fmt.Sprintf("Configuration file [%s] not exists, skipped", configFile))

		} else if err := UnmarshalYamlFile(configFile, &cfg); err != nil {
			Warn(fmt.Sprintf("Configuration file [%s] contains ivalid YAML, skipped. %v", configFile, err))
		}
	}

	// Define certificates folder
	if certFolder == "" {
		if cfg.Folder == "" {
			Fatal("CA certificates folder path is required. Define it in the config or using --ca-cert-folder flag")
		} else {
			certFolder = cfg.Folder
		}
	}
	certFolderAbs, err := filepath.Abs(certFolder)
	if err != nil {
		Fatal("CA certificates folder path [%s] is wrong. %v", certFolder, err)
	}

	caCertWrap := x509wrapper.NewCert(CACertFileName, certFolderAbs)

	if createCert && !caCertWrap.ExistsBoth() {
		createCA = true
	} else if createCA {
		Fatal("CA already exists. Recreating this cert will invalidate all signed server and client sertificates")
	}

	if createCA {
		// Create CA certificate

		Info("Creating CA certificate...\n")

		newCAcert := x509wrapper.PrepareCA(
			pkix.Name{
				Country:            []string{cfg.Country},
				Organization:       []string{cfg.Organization},
				OrganizationalUnit: []string{cfg.OrganizationalUnit},
				Locality:           []string{cfg.Locality},
				Province:           []string{cfg.Province},
				StreetAddress:      []string{cfg.StreetAddress},
				PostalCode:         []string{cfg.PostalCode},
				SerialNumber:       "",
				CommonName:         "CA Cert",
				Names:              []pkix.AttributeTypeAndValue{},
				ExtraNames:         []pkix.AttributeTypeAndValue{},
			},
			time.Now(),
			time.Now().AddDate(50, 0, 0),
		)

		// Add new CA cert and private key
		if err := caCertWrap.AddCertAndKey(newCAcert, 4096); err != nil {
			Fatal("Problem with new CA certificate: %v", err)
		}

		if err := caCertWrap.Save(nil); err != nil {
			Fatal("Problem with saving CA certificate: %v", err)
		}

		Info("Create the CA certificate successfully.")
	} else if createCert {
		Info("Loading CA certificate...\n")
		if err := caCertWrap.Load(); err != nil {
			Fatal("Problem with loading CA certificate: %v", err)
		}
	} else {
		Warn("Nothing to do. Stop\n")
		return
	}

	if createCert {
		var certConf CAConf

		Info("Creating certificate...\n")

		certConfigFile, err := filepath.Abs(certConfigFile)
		if err != nil {
			Fatal("Configuration file [%s] wrong path, skipped", certConfigFile)

		} else if _, err := os.Stat(certConfigFile); os.IsNotExist(err) {
			Fatal("Configuration file [%s] not exists, skipped", certConfigFile)

		} else if err := UnmarshalYamlFile(certConfigFile, &certConf); err != nil {
			Fatal("Configuration file [%s] contains ivalid YAML, skipped. %v", certConfigFile, err)
		}

		// Create new certificate to sign with CA
		newCertWrap := x509wrapper.NewCert(certConf.Name, "./")

		newCert := x509wrapper.PrepareCert(
			pkix.Name{
				Country:            []string{certConf.Country},
				Organization:       []string{certConf.Organization},
				OrganizationalUnit: []string{certConf.OrganizationalUnit},
				Locality:           []string{certConf.Locality},
				Province:           []string{certConf.Province},
				StreetAddress:      []string{certConf.StreetAddress},
				PostalCode:         []string{certConf.PostalCode},
				SerialNumber:       "",
				CommonName:         certConf.Name,
				Names:              []pkix.AttributeTypeAndValue{},
				ExtraNames:         []pkix.AttributeTypeAndValue{},
			},
			[]string{certConf.DNS},
			time.Now(),
			time.Now().AddDate(1, 0, 0))

		if err := newCertWrap.AddCertAndKey(newCert, 2048); err != nil {
			Fatal("make new Certificate error: %v", err)
		}

		if err := newCertWrap.Save(caCertWrap); err != nil {
			Fatal("save new Certificate error: %v", err)
		}

		Info("The new certificate was created successfully.")
	}

	Info("Completed successfully...")
}

func Info(s string) {
	fmt.Println("Info:", aurora.BrightGreen(s))
}

func Warn(s string) {
	fmt.Println(aurora.BrightYellow("Warning:"), aurora.BrightYellow(s))
}

func Fatal(s string, args ...any) {
	fmt.Println(aurora.BrightRed("Fatal:"), aurora.BrightRed(fmt.Sprintf(s, args...)))
	fmt.Println("")
	os.Exit(101)
}

func UnmarshalYamlFile(filename string, v any) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		return err
	}
	return nil
}
