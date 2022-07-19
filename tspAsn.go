package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

/*
  ASN.1 структуры, необходимые для создания/разбора TSP запросов/ответов.
  Определение в RFC3161 - https://datatracker.ietf.org/doc/html/rfc3161
*/

// Определение OID-ов, необходимых для разбора и проверки TSP запросов
var (
	oidTSPCmsSignedData         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSPTimeStampTokenContent = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// Определение разрешенных (считающихся корректными) статусов TSP ответа.
const (
	tspResponseStatusGranted         = int(0)
	tspResponseStatusGrantedWithMods = int(1)
)

// tspRequest определяет структуру TSP запроса.
//
// TimeStampReq ::= SEQUENCE {
//   version INTEGER  { v1(1) },
//   messageImprint MessageImprint,
//   reqPolicy TSAPolicyId OPTIONAL,
//   nonce INTEGER OPTIONAL,
//   certReq BOOLEAN DEFAULT FALSE,
//   extensions [0] IMPLICIT Extensions OPTIONAL }
//
// TSAPolicyId ::= OBJECT IDENTIFIER
type tspRequest struct {
	Version        int `asn1:"default:1"`
	MessageImprint tspMessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional,omitempty"`
	Nonce          *big.Int              `asn1:"optional,omitempty"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,omitempty,tag:0"`
}

// tspResp определяет структуру ответа TSA.
//
// При получении успешного ответа timeStampToken - это подписанный CMS (CMS Signed) - см. https://tools.ietf.org/html/rfc5652
//  TimeStampResp ::= SEQUENCE  {
//    status PKIStatusInfo,
//    timeStampToken TimeStampToken OPTIONAL  }
type tspResp struct {
	Status         tspPKIStatusInfo
	TimeStampToken cmsEncapsulatedContentInfoSigned `asn1:"optional,omitempty"`
}

// tspMessageImprint определяет алгоритм хеширования и хеш данных на которые создается метка времени.
//
//  MessageImprint ::= SEQUENCE  {
//    hashAlgorithm                AlgorithmIdentifier,
//    hashedMessage                OCTET STRING
//  }
type tspMessageImprint struct {
	Raw           asn1.RawContent
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// tspPKIStatusInfo определяет структуру со статусом ответа от TSA.
//
// PKIStatusInfo ::= SEQUENCE {
//   	status        PKIStatus,
// 	  statusString  PKIFreeText     OPTIONAL,
//   	failInfo      PKIFailureInfo  OPTIONAL  }
//
//   PKIStatus ::= INTEGER
type tspPKIStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional,omitempty"`
	FailInfo     asn1.BitString  `asn1:"optional,omitempty"`
}

// cmsSignedData определяет структуру CMS с подписью.
//
//  SignedData ::= SEQUENCE {
//    version CMSVersion,
//    digestAlgorithms DigestAlgorithmIdentifiers,
//    encapContentInfo EncapsulatedContentInfo,
//    certificates [0] IMPLICIT CertificateSet OPTIONAL,
//    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//    signerInfos SignerInfos }
//
//  DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
//
//  SignerInfos ::= SET OF SignerInfo
//
//  CertificateSet ::= SET OF CertificateChoices
//  RevocationInfoChoices ::= SET OF RevocationInfoChoice
type cmsSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo cmsEncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,omitempty,tag:0"`
	CRLs             []asn1.RawValue `asn1:"optional,omitempty,tag:1"`
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}

// cmsSignerInfo определяет структуру одной подписи в CMS.
//
//  SignerInfo ::= SEQUENCE {
//    version CMSVersion,
//    sid SignerIdentifier,
//    digestAlgorithm DigestAlgorithmIdentifier,
//    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//    signatureAlgorithm SignatureAlgorithmIdentifier,
//    signature SignatureValue,
//    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
type cmsSignerInfo struct {
	Version             int
	RawSignerIdentifier asn1.RawValue
	DigestAlgorithm     pkix.AlgorithmIdentifier
	SignedAttributes    []asn1.RawValue `asn1:"optional,omitempty,tag:0"`
	SignatureAlgorithm  pkix.AlgorithmIdentifier
	Signature           []byte
	UnsignedAttributes  []asn1.RawValue `asn1:"optional,omitempty,tag:1"`
}

// cmsEncapsulatedContentInfoSigned определяет структуру для вложенных в CMS с подписью данных (здесь один из вариантов cmsEncapsulatedContentInfo).
type cmsEncapsulatedContentInfoSigned struct {
	ContentType asn1.ObjectIdentifier
	Content     cmsSignedData `asn1:"explicit,tag:0"`
}

// cmsEncapsulatedContentInfo определяет структуру вложенных в CMS данных.
//
//  EncapsulatedContentInfo ::= SEQUENCE {
//    eContentType ContentType,
//    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
//
//  ContentType ::= OBJECT IDENTIFIER
type cmsEncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"optional,omitempty,explicit,tag:0"`
}

// tspAccuracy опциональное поле, которое определяют точность времени указанного
// в поле генерации даты метки (asnTSPTstInfo.genTime).
//
//  Accuracy ::= SEQUENCE {
//    seconds        INTEGER              OPTIONAL,
//    millis     [0] INTEGER  (1..999)    OPTIONAL,
//    micros     [1] INTEGER  (1..999)    OPTIONAL
//  }
type tspAccuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// tspTSTInfo представляет собой собственно метку времени, подписанную TSA.
//
//  TSTInfo ::= SEQUENCE  {
//    version                      INTEGER  { v1(1) },
//    policy                       TSAPolicyId,
//    messageImprint               MessageImprint,
//    serialNumber                 INTEGER,
//    genTime                      GeneralizedTime,
//    accuracy                     Accuracy                 OPTIONAL,
//    ordering                     BOOLEAN             DEFAULT FALSE,
//    nonce                        INTEGER                  OPTIONAL,
//    tsa                          [0] GeneralName          OPTIONAL,
//    extensions                   [1] IMPLICIT Extensions   OPTIONAL
//  }
type tspTSTInfo struct {
	Version        int `asn1:"default:1"`
	Policy         asn1.ObjectIdentifier
	MessageImprint tspMessageImprint
	SerialNumber   *big.Int
	Time           time.Time        `asn1:"generalized"`
	Accuracy       tspAccuracy      `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}
