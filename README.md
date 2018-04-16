![./artwork/logo.png](./artwork/logo.png)

Cryptore
====

[![Download](https://api.bintray.com/packages/kazakago/maven/cryptore/images/download.svg)](https://bintray.com/kazakago/maven/cryptore/_latestVersion)
[![Build Status](https://www.bitrise.io/app/436ed4113cb15072/status.svg?token=5I58EK088C0wp3UWmf75qA)](https://www.bitrise.io/app/436ed4113cb15072)
[![license](https://img.shields.io/github/license/kazakago/cryptore.svg)](LICENSE.md)

This library performs encryption and decryption byte array using [Android KeyStore System.](https://developer.android.com/training/articles/keystore.html)

## Requirement

- RSA encryption
    - Android 4.3 (API 18) or later
- AES encryption
    - Android 6.0 (API 23) or later

This is due to Android OS hardware restrictions. [More details.](https://developer.android.com/training/articles/keystore.html#SupportedAlgorithms)

## Install

Add the following gradle dependency exchanging x.x.x for the latest release.

```groovy
implementation 'com.kazakago.cryptore:cryptore:x.x.x'
```

## Usage

The following is a sample to encrypt and decrypt text using RSA encryption.

### Initialize

```java
Cryptore getCryptore(Context context, String alias) throws Exception {
    Cryptore.Builder builder = new Cryptore.Builder(alias, CipherAlgorithm.RSA);
    builder.setContext(context); //Need Only RSA on below API Lv22.
//    builder.setBlockMode(BlockMode.ECB); //If Needed.
//    builder.setEncryptionPadding(EncryptionPadding.RSA_PKCS1); //If Needed.
    return builder.build();
}
```

### Encrypt
```java
String encrypt(String plainStr) throws Exception {         
    byte[] plainByte = plainStr.getBytes();         
    EncryptResult result = getCryptore().encrypt(plainByte);
    return Base64.encodeToString(result.getBytes(), Base64.DEFAULT);
}
```

### Decrypt
```java
String decrypt(String encryptedStr) throws Exception {
    byte[] encryptedByte = Base64.decode(encryptedStr, Base64.DEFAULT);
    DecryptResult result = getCryptore().decrypt(encryptedByte, null);
    return new String(result.getBytes());
}
```

Refer to the sample module ([Java](https://github.com/KazaKago/Cryptore/tree/master/samplejava) & [Kotlin](https://github.com/KazaKago/Cryptore/tree/master/samplekotlin)) for details.

For other encryption options supported by Android, please see [here.](https://developer.android.com/training/articles/keystore.html#SupportedAlgorithms)

## Default encryption mode

- RSA encryption
    - BlockMode : ECB
    - Padding : PKCS1Padding
- AES encryption
    - BlockMode : CBC
    - Padding : PKCS7Padding

## License
MIT License

Copyright (c) 2017 KazaKago

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
