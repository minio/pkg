// Copyright (c) 2015-2023 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package subnet

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/minio/pkg/v3/licverifier"
)

const (
	publicKeyPath = "/downloads/license-pubkey.pem"

	// https://subnet.min.io/downloads/license-pubkey.pem
	publicKeyProd = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEaK31xujr6/rZ7ZfXZh3SlwovjC+X8wGq
qkltaKyTLRENd4w3IRktYYCRgzpDLPn/nrf7snV/ERO5qcI7fkEES34IVEr+2Uff
JkO2PfyyAYEO/5dBlPh1Undu9WQl6J7B
-----END PUBLIC KEY-----`
	// https://localhost:9000/downloads/license-pubkey.pem
	publicKeyDev = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbo+e1wpBY4tBq9AONKww3Kq7m6QP/TBQ
mr/cKCUyBL7rcAvg0zNq1vcSrUSGlAmY3SEDCu3GOKnjG/U4E7+p957ocWSV+mQU
9NKlTdQFGF3+aO6jbQ4hX/S5qPyF+a3z
-----END PUBLIC KEY-----`
)

// LicenseValidator validates the MinIO license.
type LicenseValidator struct {
	Client            http.Client
	LicenseFilePath   string
	pubKeyURL         string
	offlinePubKey     []byte
	LicenseToken      string
	ExpiryGracePeriod time.Duration
}

// LicenseValidatorParams holds parameters for creating a new LicenseValidator.
type LicenseValidatorParams struct {
	TLSClientConfig   *tls.Config
	LicenseFilePath   string
	LicenseToken      string
	ExpiryGracePeriod time.Duration
	DevMode           bool
}

// BaseURL returns the base URL for subnet.
func BaseURL(devMode bool) string {
	if devMode {
		subnetURLDev := os.Getenv("SUBNET_URL_DEV")
		if len(subnetURLDev) > 0 {
			return subnetURLDev
		}
		return "http://localhost:9000"
	}

	return "https://subnet.min.io"
}

// NewLicenseValidator returns a new LicenseValidator using the provided tls client Config,
// and license file path. If the path is empty,  it will look for minio.license in the
// current working directory. If `devMode` is true, the validator will connect to locally
// running SUBNET instance to download the public key or use the bundled dev key.
func NewLicenseValidator(params LicenseValidatorParams) (*LicenseValidator, error) {
	licPath := params.LicenseFilePath
	licToken := params.LicenseToken
	if licToken == "" {
		licToken = os.Getenv("MINIO_LICENSE")
	}
	if licPath == "" && licToken == "" {
		// if license file path is not provided, and also
		// not set in env variable, expect it to be present
		// in the current working directory
		pwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		licPath = pwd + "/minio.license"
	}
	client := http.Client{
		Timeout: 0,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).DialContext,
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       params.TLSClientConfig,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 10 * time.Second,
		},
	}
	lv := LicenseValidator{
		Client:            client,
		LicenseFilePath:   licPath,
		LicenseToken:      licToken,
		ExpiryGracePeriod: params.ExpiryGracePeriod,
	}
	lv.Init(params.DevMode)
	return &lv, nil
}

// Init initializes the LicenseValidator.
func (lv *LicenseValidator) Init(devMode bool) {
	lv.pubKeyURL = fmt.Sprintf("%s%s", BaseURL(devMode), publicKeyPath)
	lv.offlinePubKey = []byte(publicKeyProd)
	if devMode {
		lv.offlinePubKey = []byte(publicKeyDev)
	}
}

// downloadSubnetPublicKey will download the current subnet public key.
func (lv *LicenseValidator) downloadSubnetPublicKey() ([]byte, error) {
	resp, err := lv.Client.Get(lv.pubKeyURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download public key from %s. response [%d:%s]", lv.pubKeyURL, resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParseLicense parses the license with the public key and return it's information.
// Public key is downloaded from subnet. If there is an error downloading the public key
// it will use the bundled public key instead.
func (lv *LicenseValidator) ParseLicense(license string) (*licverifier.LicenseInfo, error) {
	publicKey, e := lv.downloadSubnetPublicKey()
	if e != nil {
		// there was an issue getting the subnet public key
		// use hardcoded public keys instead
		publicKey = lv.offlinePubKey
	}

	lvr, e := licverifier.NewLicenseVerifier(publicKey)
	if e != nil {
		return nil, e
	}

	li, e := lvr.Verify(license, jwt.WithAcceptableSkew(lv.ExpiryGracePeriod))
	return &li, e
}

// ValidateLicense validates the license file.
func (lv *LicenseValidator) ValidateLicense() (*licverifier.LicenseInfo, error) {
	if lv.LicenseToken == "" && lv.LicenseFilePath == "" {
		return nil, fmt.Errorf("MinIO license not found")
	}

	var lic string
	if lv.LicenseToken != "" {
		lic = lv.LicenseToken
	} else {
		licData, err := os.ReadFile(lv.LicenseFilePath)
		if err != nil {
			return nil, err
		}
		lic = string(licData)
	}

	return lv.ParseLicense(lic)
}

func getDurationForNextLicenseCheck(li *licverifier.LicenseInfo) time.Duration {
	if li.ExpiresAt.Before(time.Now()) {
		// expired, within grace period. schedule daily
		return time.Hour * 24
	}
	// not expired, schedule to check just after expiry
	return time.Until(li.ExpiresAt.Add(time.Second))
}

func (lv *LicenseValidator) scheduleNextLicenseCheck(li *licverifier.LicenseInfo, acceptedPlans []string, licExpiredChan chan<- string) {
	duration := getDurationForNextLicenseCheck(li)
	timer := time.NewTimer(duration)
	defer timer.Stop()

	ctxt := context.Background()
	for {
		select {
		case <-timer.C:
			li, err := lv.ValidateEnterpriseLicense(acceptedPlans, licExpiredChan)
			if err != nil {
				licExpiredChan <- err.Error()
				return
			}
			timer.Reset(getDurationForNextLicenseCheck(li))
		case <-ctxt.Done():
			return
		}
	}
}

// ValidateEnterpriseLicense validates the ENTERPRISE license file.
// Since there are multiple variants of ENTERPRISE licenses, ones
// accepted by the application can be passed as `acceptedPlans`.
// TRIAL licenses do not get grace period after expiry.
func (lv *LicenseValidator) ValidateEnterpriseLicense(acceptedPlans []string, licExpiredChan chan<- string) (*licverifier.LicenseInfo, error) {
	li, err := lv.ValidateLicense()
	if err != nil {
		return nil, err
	}

	accepted := false
	for _, plan := range acceptedPlans {
		if plan == li.Plan {
			accepted = true
			break
		}
	}
	if !accepted {
		return nil, fmt.Errorf("this software is only available for license plans %v", strings.Join(acceptedPlans, ", "))
	}

	if li.ExpiresAt.Before(time.Now()) {
		if li.IsTrial || li.Plan == "TRIAL" {
			// no grace period for trial
			return nil, fmt.Errorf("trial license has expired on %v", li.ExpiresAt)
		}
	}

	// validation successful. start a background routine to validate the license
	// - daily if already expired (within grace period)
	// - just after expiry if not expired
	if licExpiredChan != nil {
		// if the expiry channel is nil, it means client doesn't want to be notified
		// when license expires. In that case we don't schedule the background check.
		go lv.scheduleNextLicenseCheck(li, acceptedPlans, licExpiredChan)
	}

	return li, nil
}
