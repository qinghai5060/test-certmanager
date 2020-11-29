package controllers

import (
	"bytes"
	"certmanager/models"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"math/big"
	"net"
	"net/http"
	"time"
)

type CAController struct {
	beego.Controller
}


// @Title CreateCA
// @Description create CA
// @Param	body		body 	models.CARequest	true		"ca request body"
// @Success 201 {int}  models.CA
// @Failure 400 invalid input
// @router /v1/ca [post]
func (c *CAController) CreateCA() {
	if c.Ctx.Input.RequestBody == nil {
		setErrorResponse(c.Ctx, http.StatusBadRequest, []byte("bad request"))
		return
	}
	caRequest := new(models.CARequest)
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, caRequest); err != nil {
		setErrorResponse(c.Ctx, http.StatusBadRequest, []byte("invalid input"))
		return
	}

	var pub interface{}
	var priv interface{}
	var err error

	switch caRequest.SigningAlgorithm {
	case "", "ecdsa":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			setErrorResponse(c.Ctx, http.StatusInternalServerError, []byte(err.Error()))
			return
		}
		pub = priv.(*ecdsa.PrivateKey).Public()
	case "ed25519":
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			setErrorResponse(c.Ctx, http.StatusInternalServerError, []byte(err.Error()))
			return
		}
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			setErrorResponse(c.Ctx, http.StatusInternalServerError, []byte(err.Error()))
			return
		}

		pub = priv.(*rsa.PrivateKey).PublicKey
	default:
		setErrorResponse(c.Ctx, http.StatusNotImplemented, []byte("invalid algo"))
		return
	}

	serialNumLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialNumLimit)

	notBefore := time.Now()
	fmt.Printf("time.now is :%v\n", notBefore)
	notAfter := notBefore.Add(time.Hour * 24 * 30 * time.Duration(caRequest.Validity))
	keyUsage := x509.KeyUsageDigitalSignature
	if caRequest.SigningAlgorithm == "rsa" {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	template := &x509.Certificate{
		PublicKey:    pub,
		SerialNumber: serialNum,
		Subject: pkix.Name{
			Organization: []string{caRequest.Organisation},
			CommonName:   caRequest.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		DNSNames:              []string{"100.107.148.107.xip.io"},
		IPAddresses:           []net.IP{net.ParseIP("100.107.148.107")},
	}

	if caRequest.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		setErrorResponse(c.Ctx, http.StatusInternalServerError, []byte(err.Error()))
		return
	}

	certBuf := &bytes.Buffer{}
	if err := pem.Encode(certBuf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}); err != nil {
		setErrorResponse(c.Ctx, http.StatusInternalServerError, []byte(err.Error()))
		return
	}

	keyBytes, err := json.Marshal(priv)
	if err != nil {
		setErrorResponse(c.Ctx, http.StatusInternalServerError, []byte(err.Error()))
		return
	}
	keyBuf := &bytes.Buffer{}
	if err := pem.Encode(keyBuf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		setErrorResponse(c.Ctx, http.StatusInternalServerError, []byte(err.Error()))
		return
	}

	 res := &models.CA{
	 	CACert: keyBuf.String(),
	 	CAKey: certBuf.String(),
	 }

	 bytesRes,err := json.Marshal(res)
	 if err != nil {
	 	setErrorResponse(c.Ctx, http.StatusInternalServerError, []byte(err.Error()))
		 return
	 }

	 c.Ctx.Output.Body(bytesRes)
	c.Ctx.Output.SetStatus(http.StatusCreated)
}

func (c *CAController) GetCA() {

}
func (c *CAController) ListCAs() {

}

func (c *CAController) DeleteCA() {

}

func setErrorResponse(ctx *context.Context, status int, body []byte) {
	ctx.Output.SetStatus(status)
	ctx.Output.Body(body)
}
