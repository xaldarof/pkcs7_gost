import 'dart:io';
import 'dart:typed_data';

import 'package:dart_crypto_lib/dart_crypto_lib.dart';
import 'package:pkcs7_gost/src/common.dart';
import 'package:pkcs7_gost/src/pkcs7_builder.dart';
import 'package:pkcs7_gost/src/x509.dart';

void main() {
  const String message = "message";
  final pkcs7Builder = Pkcs7Builder();
  final cer = CryptoDart.loadCertificateFromCer(File(
          "C:/Users/User/AndroidStudioProjects/pkcs7_gost/test/Salimov_Baxodir_Kobil_O‘g‘li (2).cer")
      .readAsBytesSync());
  final privateKey = CryptoDart.loadPrivateKeyFromPrk(File(
          "C:/Users/User/AndroidStudioProjects/pkcs7_gost/test/Salimov_Baxodir_Kobil_O‘g‘li (2).prk")
      .readAsBytesSync());
  final cert = X509.fromPem(cer.plain ?? "");
  pkcs7Builder.addCertificate(cert);

  final signerInfo = Pkcs7SignerInfoBuilder.rsa(
      issuer: cert,
      privateKey: privateKey,
      digestAlgorithm: HashAlgorithm.ozdst1106);

  final digestOfDigest = CryptoDart.calculateHashOzdst1106(
          CryptoDart.calculateHashOzdst1106(message.codeUnits))
      .reversed
      .toList();
  signerInfo.addSMimeDigest(digest: digestOfDigest.uInt8List);

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
