# pyGmSSL

pyGmSSL is the Python binding to the GmSSL library.

The Python wrappers of pyGmSSL are very similar to the GmSSL v3 C API. Most class/struct and function names are the same, and the arguments are in the same order. Here is an example of encrypting a block of message by SM4 cipher in both C and Python.

```C
#include <gmssl/sm4.h>
#include <gmssl/rand.h>

unsigned char key[SM4_KEY_SIZE] = "1234567812345678";
rand_bytes(key, sizeof(key));

unsigned char block[SM4_BLOCK_SIZE] = "1234567812345678";

SM4_KEY sm4_key;
sm4_set_encrpt_key(&sm4_key, key);
sm4_encrypt(&sm4_key, block, block);

sm4_set_decrpt_key(&sm4_key, key);
sm4_decrypt(&sm4_key, block, block);
```

The corresponding Python code:

```python
import GmSSL

sm4_key = GmSSL.SM4_KEY()
sm4_key.set_encrypt_key(b"1234567812345678")
ciphertext = sm4_key.encrypt(b"1234567812345678")

sm4_key.set_decrypt_key(b"1234567812345678")
plaintext = sm4_key.decrypt(ciphertext)
```

# SM2

### 加密解密

```python
import GmSSL

keypair = GmSSL.sm2_generate_keypair()
public_key = keypair.public_key
private_key = keypair.private_key
plaintext = b'hello world'
# 加密
ciphertext = GmSSL.sm2_encrypt(public_key, plaintext)
# 解密
decrypted = GmSSL.sm2_decrypt(private_key, ciphertext)
# assert plaintext == decrypted
```

### 签名验签

```python
import GmSSL

keypair = GmSSL.sm2_generate_keypair()
public_key = keypair.public_key
private_key = keypair.private_key
message = b'hello world'
# 签名
signature = GmSSL.sm2_sign(private_key, public_key, message)
# 验签
verified = GmSSL.sm2_verify(private_key, public_key, message, signature)
# assert verified == True
```

### ASN.1 DER 编码

加密和签名的数据都是 ASN.1 DER 编码，如果要解码得到原始数据，可以参考下面的代码，需要安装 pycryptodomex

```python
# ASN.1 DER 解码

import GmSSL
from Cryptodome.Util.asn1 import DerSequence, DerOctetString, DerInteger

keypair = GmSSL.sm2_generate_keypair()
public_key = keypair.public_key
private_key = keypair.private_key
plaintext = b'hello world'
# 加密
ciphertext = GmSSL.sm2_encrypt(public_key, plaintext)
seq_der = DerSequence()
origin_data = seq_der.decode(ciphertext)
# c1: point(x, y) 64bytes
# c2: ciphertext len(data)
# c3: hash 32bytes
# der order: c1x c1y hash ciphertext
c1x = origin_data[0]
c1y = origin_data[1]
c3 = DerOctetString().decode(origin_data[2]).payload
c2 = DerOctetString().decode(origin_data[3]).payload
raw_ciphertext = c1x.to_bytes(32, "big") + c1y.to_bytes(32, "big") + c3 + c2

message = b'hello world'
# 签名
signature = GmSSL.sm2_sign(private_key, public_key, message)
seq_der = DerSequence()
origin_sign = seq_der.decode(signature)
r = origin_sign[0]
s = origin_sign[1]
raw_signature = '%064x%064x' % (r, s)
```

