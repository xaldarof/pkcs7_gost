import 'dart:typed_data';

import 'package:dart_crypto_lib/dart_crypto_lib.dart';

class Ozdst1106DigestProvider {
  static Uint8List process(Uint8List message) =>
      CryptoDart.calculateHashOzdst1106(message).uInt8List;
}
