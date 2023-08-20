package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/b-sn/passwd"
	"github.com/b-sn/x509wrapper"
	"github.com/google/uuid"
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
	ConvertToPKCS12    bool   `yaml:"to_pkcs12"`
}

var (
	configFile, certFolder                     string
	createCA, createCert, testCert, withUserID bool
	certConfigFile                             string
	SAN_OID                                    []int = asn1.ObjectIdentifier{2, 5, 29, 17} // OID for Subject Alternative Name
)

func main() {

	// Catch panic and exit with error code
	// This does not print stack trace in case of Fatal is called
	// But it runs after other defers, so temporary files will be removed
	defer func() {
		if r := recover(); r != nil {
			os.Exit(101)
		}
	}()

	var err error

	// TODO: Combine flags for create certs and path to config file to one flag: create-cert-from-config
	flag.StringVar(&configFile, "config-file", defCAConfigFile, "CA certificate configuration, required for it creation")
	flag.StringVar(&certFolder, "ca-cert-folder", "", "CA certificates folder")
	flag.BoolVar(&createCA, "create-ca", false, "Need to create CA certificate")
	flag.BoolVar(&createCert, "create-cert", false, "Need to create new certificate")
	flag.StringVar(&certConfigFile, "cert-config", defCertConfigFile, "New certificate name")

	// Flag to check connection using created certificate
	flag.BoolVar(&testCert, "test", false, "Need to test a created certificate")

	// Flag to generate user ID to certificate
	flag.BoolVar(&withUserID, "with-user-id", false, "Generate user ID to certificate")

	flag.Parse()

	// Get CA configuration
	var cfg CAConf
	if configFile != "" {
		cfg, err = readConfig(configFile)
		if err != nil {
			Warn(err.Error())
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

	if !createCA && !createCert && !testCert {
		Warn("Nothing to do. Stop\n")
		return
	}

	if createCA {
		// Create CA certificate

		Info("Creating CA certificate...\n")

		cfg.Name = "CA Cert"
		newCAcert := x509wrapper.PrepareCA(
			buildPkixName(cfg),
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

		Info("The CA certificate was created successfully.")

	} else if createCert || testCert {
		Info("Loading CA certificate...\n")
		if err := caCertWrap.Load(); err != nil {
			Fatal("Problem with loading CA certificate: %v", err)
		}
	}

	var certConf CAConf

	if createCert || testCert {
		certConf, err = readConfig(certConfigFile)
		if err != nil {
			Fatal(err.Error())
		}
	}

	newCertWrap := x509wrapper.NewCert(certConf.Name, certConf.Folder)

	if createCert {
		Info("Creating certificate...\n")

		// Create new certificate to sign with CA
		newCert := x509wrapper.PrepareCert(
			buildPkixName(certConf),
			[]string{certConf.DNS},
			time.Now(),
			time.Now().AddDate(1, 0, 0),
			[]pkix.Extension{},
		)

		if withUserID {

			// Generate user ID to certificate
			userId := uuid.New().String()

			// Convert user ID to ASN1
			extVal, err := asn1.Marshal([]asn1.RawValue{
				{Tag: 19, Class: 2, Bytes: []byte(userId)},
			})
			if err != nil {
				Fatal("ASN1 marshaling error: %v", err)
			}

			// Add user ID to certificate
			newCert.ExtraExtensions = append(newCert.ExtraExtensions, pkix.Extension{
				Id:       SAN_OID,
				Critical: false,
				Value:    extVal,
			})
		}

		if err := newCertWrap.AddCertAndKey(newCert, 2048); err != nil {
			Fatal("make new Certificate error: %v", err)
		}

		if err := newCertWrap.Save(caCertWrap); err != nil {
			Fatal("save new Certificate error: %v", err)
		}

		if certConf.ConvertToPKCS12 {
			passGenerator := passwd.GetGenerator(passwd.AlphaNumeric)
			pass := passGenerator(24)
			if err := newCertWrap.SaveAsPKCS12(pass); err != nil {
				Fatal("save new Certificate as PKCS12 error: %v", err)
			}
			fmt.Println(aurora.BrightYellow("PKCS12 password [save it]:"), aurora.BrightGreen(pass))
		}

		Info("The new certificate was created successfully.")
	}

	if testCert {
		Info("Testing certificate...\n")

		tmpName := certConf.Name
		certConf.Name = "Server Temp Cert"

		// For testing we need to create temporary server certificate
		tempServerCertWrap := x509wrapper.NewCert(certConf.Name, certConf.Folder)

		tempServerCert := x509wrapper.PrepareCert(
			buildPkixName(certConf),
			[]string{certConf.DNS},
			time.Now(),
			time.Now().AddDate(1, 0, 0),
			[]pkix.Extension{},
		)

		if err := tempServerCertWrap.AddCertAndKey(tempServerCert, 2048); err != nil {
			Fatal("make new Test Server Certificate error: %v", err)
		}

		if err := tempServerCertWrap.Save(caCertWrap); err != nil {
			Fatal("save new Test Server Certificate error: %v", err)
		}
		defer os.Remove(tempServerCertWrap.CertFile)
		defer os.Remove(tempServerCertWrap.KeyFile)

		certConf.Name = tmpName

		wg := sync.WaitGroup{}
		wg.Add(1)

		// Run server with new certificate in goroutine
		go func() {

			// load CA certificate file and add it to list of client CAs
			caCertFile, err := os.ReadFile(caCertWrap.CertFile)
			if err != nil {
				Fatal("error reading CA certificate: %v", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCertFile)

			s := http.Server{
				Addr: fmt.Sprintf(":%d", 8880),
				// Handler: e,
				TLSConfig: &tls.Config{
					ClientCAs:  caCertPool,
					ClientAuth: tls.RequireAndVerifyClientCert,
				},
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
					Warn("SERVER: No client certificate presented!")
					return
				}

				var extVal []asn1.RawValue
				var userUUID string

			CertLoop:
				for _, cert := range r.TLS.PeerCertificates {
					for _, ext := range cert.Extensions {
						if !ext.Id.Equal(SAN_OID) {
							continue
						}
						if _, err := asn1.Unmarshal(ext.Value, &extVal); err != nil {
							Fatal("SERVER: ASN1 unmarshaling error: %v", err)
						}
						for _, val := range extVal {
							if val.Tag != 19 {
								continue
							}
							userUUID = string(val.Bytes)
							break CertLoop
						}
					}
				}

				if userUUID != "" {
					Info(fmt.Sprintf("SERVER: Got request from client: %#v\n", userUUID))
				} else {
					Warn("SERVER: No user ID in certificate")
				}
			}

			http.HandleFunc("/", handler)

			Info("SERVER: Starting ...\n")

			wg.Done()

			err = s.ListenAndServeTLS(
				tempServerCertWrap.CertFile,
				tempServerCertWrap.KeyFile)
			if err != http.ErrServerClosed {
				Fatal("SERVER: error starting: %v", err)
			}

		}()

		wg.Wait()

		// Load cert and key from files
		clientCert, err := tls.LoadX509KeyPair(newCertWrap.CertFile, newCertWrap.KeyFile)
		if err != nil {
			Fatal("Error loading cert and key: %v", err)
		}

		// Create TLS config with client certificate
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{clientCert},
			InsecureSkipVerify: true,
		}

		// Create client with TLS config
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			Timeout: 5 * time.Second,
		}

		url := fmt.Sprintf("https://%s:8880", certConf.DNS)

		// Make request
		resp, err := client.Get(url)
		if err != nil {
			Fatal("Client request error: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			Fatal("Error reading response: %v", err)
		}

		Info("Server response:")
		Info(string(body))
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
	panic("panic")
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

func readConfig(configFile string) (cfg CAConf, err error) {

	configFile, err = filepath.Abs(configFile)

	if err != nil {
		return cfg, fmt.Errorf("configuration file [%s] wrong path, skipped", configFile)
	}

	if _, err_ := os.Stat(configFile); os.IsNotExist(err_) {
		return cfg, fmt.Errorf("configuration file [%s] not exists, skipped", configFile)
	}

	if err_ := UnmarshalYamlFile(configFile, &cfg); err_ != nil {
		return cfg, fmt.Errorf(
			"configuration file [%s] contains ivalid YAML, skipped. %v",
			configFile,
			err_,
		)
	}

	return cfg, nil
}

func buildPkixName(conf CAConf) pkix.Name {
	return pkix.Name{
		Country:            []string{conf.Country},
		Organization:       []string{conf.Organization},
		OrganizationalUnit: []string{conf.OrganizationalUnit},
		Locality:           []string{conf.Locality},
		Province:           []string{conf.Province},
		StreetAddress:      []string{conf.StreetAddress},
		PostalCode:         []string{conf.PostalCode},
		SerialNumber:       "",
		CommonName:         conf.Name,
		Names:              []pkix.AttributeTypeAndValue{},
		ExtraNames:         []pkix.AttributeTypeAndValue{},
	}
}
