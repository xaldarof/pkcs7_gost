import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:pkcs7_gost/pkcs7_gost.dart';
import 'package:pkcs7_gost/src/common.dart';
import 'package:pkcs7_gost/src/pkcs7_builder.dart';
import 'package:pkcs7_gost/src/x509.dart';

void main() {
  final pkcs7Builder = Pkcs7Builder();
  final cert = X509.fromPem("""
  -----BEGIN CERTIFICATE-----
MIIBzzCCAXegAwIBAgIJAI9LkZejkADQMAoGCCqGSM49BAMCMIGNMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNj
bzEaMBgGA1UECgwRSW50ZXJuZXQgU29sdXRpb25zMRQwEgYDVQQLDAtBcHBsaWNh
dGlvbjEmMCQGA1UEAwwdSW50ZXJuZXQgU29sdXRpb25zIFRlc3QgQ2VydGlmaWNh
dGUwHhcNMjAwMzA5MDgwOTU2WhcNMjEwMzA5MDgwOTU2WjCBjTELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28x
GjAYBgNVBAoMEUluZGVybmV0IFNvbHV0aW9uczEUMBIGA1UECwwLQXBwbGljYXRp
b24xJjAkBgNVBAMMH0luZGVybmV0IFNvbHV0aW9ucyBUZXN0IENlcnRpZmljYXRl
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+5p59ZdFrCJqb7LJqR96nCmq7u6Z
vHn/Bo8h5MK4C+5n4N0VACPrZzZs3WQilNtOZv10fQH5P5rqhAnJ4ELlFqKNsMGU
wDgYDVR0PAQH/BAQDAgKkMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAM
BgNVHRMBAf8EAjAAMCsGA1UdIwQkMCKAIGYuY4O2c4rR+fjzwhomELiJjPEhgiGo
t3sksC2POKUZMAoGCCqGSM49BAMCA0gAMEUCIQDxGc7p7tu0V9yROv3wNj02Q78m
WtMkNmiVrN0/d/jScQIgTNgxPvjqDZxBKht/pw0L0bZ6LP5wzQkjLnG9f3ZcEaI=
-----END CERTIFICATE-----
""");
  pkcs7Builder.addCertificate(cert);

  final signerInfo = Pkcs7SignerInfoBuilder.rsa(
      issuer: cert,
      privateKey: BigInt.parse("source"),
      digestAlgorithm: HashAlgorithm.ozdst1106);

  signerInfo.addSMimeDigest(digest: Uint8List(1));

  final tsq = signerInfo.generateTSQ();
  // final tsr = await myTimestampSign!(tsq);
  // if (tsr != null) {
  //   signerInfo.addTimestamp(tsr: TimestampResponse.fromDer(tsr));
  // }

// Add the signature information
  pkcs7Builder.addSignerInfo(signerInfo);

// Add a certificate revocation list
//     pkcs7Builder.addCRL(CertificateRevocationList.fromPem("crl"));

  final pkcs7 = pkcs7Builder.build();
  print(pkcs7);
  print(pkcs7.pem);
}
