# Major Differences Between the Various HTTP ECE Versions

## aes128gcm
* Most current version as of 2017/01
* `salt`, `rs`, and `key_id` now all contained as preamble for the encrypted content.
* Sender's public DH key value is sent as the `dh` parameter of the `Crypto-Key` header
    * The `Encryption` header is no longer required.
* The context string `WebPush: info\x00` + Receiver's raw public key + Sender's raw public key
* `keyinfo` string set to `Content-Encoding: aes128gcm\x00`
* `nonceinfo` string set to `Content-Encoding: nonce\x00`
* padding is at the end of a record, a delimiter (2 for the last record, 1 for
  all others) followed by any number of zeros

## aesgcm
* `salt` contained as 'salt' parameter of the `Encryption` header
* `key_id` contained as `keyid` parameter of the `Crypto-Key` header
* Sender's public DH key value is sent as the `dh` parameter of the `Crypto-Key` header
* The context string is: `P-256\x00\x00\x41` + Receiver's raw public key + `\x00\x41` + Sender's raw public key
* `keyinfo` string set to `Content-Encoding: aesgcm\x00` + context_string 
* `nonceinfo` string set to `Content-Encoding: nonce` + context_string

## aesgcm128
* Most obsolete version
* `salt` contained as 'salt' parameter of the `Encryption` header
* `key_id` contained as `keyid` parameter of the `Encryption-Key` header
* Sender's public DH key value is sent as the `dh` parameter of the `Encryption-Key` header
* The context string is: `P-256\x00\x00\x41` + Receiver's raw public key + `\x00\x41` + Sender's raw public key
* `keyinfo` string set to `Content-Encoding: aesgcm128`
* `nonceinfo` string set to `Content-Encoding: nonce`
* padding between chunks is only 1 octet.
