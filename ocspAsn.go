package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

/*
  ASN.1 структуры, необходимые для создания/разбора OCSP запросов/ответов.
  Определение в RFC6960 - https://www.rfc-editor.org/rfc/rfc6960.html
*/

// Определение OID-ов, необходимых для создания/разбора OCSP запросов/ответов
var (
	oidOCSPNonceExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	oidOCSPBasicResponse  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
)

// ocspRequest определяет структуру OCSP запроса.
//
// OCSPRequest     ::=     SEQUENCE {
//   tbsRequest                  TBSRequest,
//   optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
type ocspRequest struct {
	TBSRequest ocspTBSRequest
	Signature  asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// ocspResponse определяет структуру OCSP ответа.
//  OCSPResponse ::= SEQUENCE {
//    responseStatus         OCSPResponseStatus,
//    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
//
//  OCSPResponseStatus ::= ENUMERATED {
//    successful            (0),  -- Response has valid confirmations
//    malformedRequest      (1),  -- Illegal confirmation request
//    internalError         (2),  -- Internal error in issuer
//    tryLater              (3),  -- Try again later
//    -- (4) is not used
//    sigRequired           (5),  -- Must sign the request
//    unauthorized          (6)   -- Request unauthorized
//  }
type ocspResponse struct {
	ResponseStatus asn1.Enumerated
	ResponseBytes  ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

// ocspTBSRequest определяет опционально подписываемое тело OCSP запроса.
//
// TBSRequest      ::=     SEQUENCE {
//   version             [0]     EXPLICIT Version DEFAULT v1,
//   requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
//   requestList                 SEQUENCE OF Request,
//   requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
type ocspTBSRequest struct {
	Version           int           `asn1:"default:0,explicit,tag:0,optional"`
	RequestorName     asn1.RawValue `asn1:"explicit,tag:1,optional"`
	RequestList       []ocspSingleRequest
	RequestExtensions []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

// ocspSingleRequest запрос о статусе одного сертификата с указанным CertID.
//
// Request         ::=     SEQUENCE {
//   reqCert                     CertID,
//   singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
type ocspSingleRequest struct {
	ReqCert                 ocspCertID
	SingleRequestExtensions []pkix.Extension `asn1:"explicit,tag:0,optional"`
}

// ocspCertID определяет сертификат статус которого получаем с помощью OCSP.
//
// CertID          ::=     SEQUENCE {
//   hashAlgorithm       AlgorithmIdentifier,
//   issuerNameHash      OCTET STRING, -- Hash of issuer's DN
//   issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
//   serialNumber        CertificateSerialNumber }
type ocspCertID struct {
	Raw           asn1.RawContent
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

// ocspResponseBytes определяет тип и содержание тела OCSP ответа, содержащего статус запрошенного сертификата(-ов).
type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

// ocspBasicResponse определяет структуру тела OCSP ответа для OID-а id-pkix-ocsp-basic ("1.3.6.1.5.5.7.48.1.1")
type ocspBasicResponse struct {
	TBSResponseData    ocspResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// ocspResponseData определяет структуру подписанной части ocspBasicResponse.
type ocspResponseData struct {
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []ocspSingleResponse
	Extensions     []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

// ocspSingleResponse представляет собой статус одного сертификата в ocspBasicResponse.
type ocspSingleResponse struct {
	CertID           ocspCertID
	CertStatusRaw    asn1.RawValue
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}
