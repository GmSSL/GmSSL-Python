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

