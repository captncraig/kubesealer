package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/bitnami-labs/sealed-secrets/pkg/crypto"
	"github.com/gopherjs/jquery"
	localStorage "github.com/oskca/gopherjs-localStorage"
	yaml "gopkg.in/yaml.v2"
	"k8s.io/client-go/util/cert"
)

var j = jquery.NewJQuery

func main() {
	if storedKey := localStorage.GetItem("pubKey"); storedKey != "" {
		j("#publicKey").SetText(storedKey)
	}
	j("#publicKey").On(jquery.BLUR, func(e jquery.Event) {
		val := e.Target.Get("value")
		localStorage.SetItem("pubKey", val.String())
	})
	j("#seal").On(jquery.CLICK, func(jquery.Event) {
		j("#output").SetText("Sealing...")
		var err error
		defer func() {
			if err != nil {
				j("#output").SetText("ERROR: " + err.Error())
			}
		}()
		pubStr := j("#publicKey").Text()
		var certs []*x509.Certificate
		certs, err = cert.ParseCertsPEM([]byte(pubStr))
		if err != nil {
			return
		}

		// ParseCertsPem returns error if len(certs) == 0, but best to be sure...
		if len(certs) == 0 {
			err = errors.New("Failed to read any certificates")
			return
		}

		cert, ok := certs[0].PublicKey.(*rsa.PublicKey)
		if !ok {
			err = errors.New("Expected RSA public key but found something else")
			return
		}

		ss := &SealedSecret{}
		ss.Name = (j("#secretName").Val())
		ss.Namespace = (j("#secretNamespace").Val())
		ss.APIVersion = "bitnami.com/v1alpha1"
		ss.Kind = "SealedSecret"

		ss.Spec.EncryptedData = map[string]string{}
		j(".secret-data-row").Each(func(i int, el interface{}) {
			je := j(el)
			key := je.Find(".secret-data-key").Val()
			val := je.Find(".secret-data-value").Val()
			cipher, err2 := crypto.HybridEncrypt(rand.Reader, cert, []byte(val), []byte(fmt.Sprintf("%s/%s", ss.Namespace, ss.Name)))
			ss.Spec.EncryptedData[key] = base64.StdEncoding.EncodeToString(cipher)
			if err2 != nil {
				err = err2
			}
		})
		if err != nil {
			return
		}
		dat, _ := yaml.Marshal(ss)

		j("#output").SetText(string(dat) + "\n")
	})
}

// Loading the cannonical types causes all kinds of syscall errors in gopherjs.
// I'm guessing because of all the code-generation nonsense going on. Just make shadow types to yamlize

type SealedSecret struct {
	TypeMeta   `yaml:",inline"`
	ObjectMeta `yaml:"metadata,omitempty"`

	Spec SealedSecretSpec `yaml:"spec"`

	Type SecretType `yaml:"type,omitempty" protobuf:"bytes,3,opt,name=type,casttype=SecretType"`
}

type SecretType string

type SealedSecretSpec struct {
	// Data is deprecated and will be removed eventually. Use per-value EncryptedData instead.
	Data          []byte            `yaml:"data,omitempty"`
	EncryptedData map[string]string `yaml:"encryptedData"`
}

type TypeMeta struct {
	Kind string `yaml:"kind,omitempty" protobuf:"bytes,1,opt,name=kind"`

	APIVersion string `yaml:"apiVersion,omitempty" protobuf:"bytes,2,opt,name=apiVersion"`
}

type ObjectMeta struct {
	Name        string            `yaml:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	Namespace   string            `yaml:"namespace,omitempty" protobuf:"bytes,3,opt,name=namespace"`
	Labels      map[string]string `yaml:"labels,omitempty" protobuf:"bytes,11,rep,name=labels"`
	Annotations map[string]string `yaml:"annotations,omitempty" protobuf:"bytes,12,rep,name=annotations"`
}
