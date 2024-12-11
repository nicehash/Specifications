# NiceHash traffic detection

#### Introduction
NiceHash HMAC solution is used to identify traffic originating from the NiceHash servers.

NiceHash uses `key`/`secret` to encode `timestamp` in `mining.subscribe`. Example:

```json
{"id":1,"method":"mining.subscribe","params":["NiceHash/1.0.0","1662637786319","3e747837e632920e8cd11453c2558233e3822489a20d828fdf205a149b064afc"]}
```

```
1662637786319 <- timestamp

3e747837e632920e8cd11453c2558233e3822489a20d828fdf205a149b064afc <- encoded timestamp
```

Pool `host`, `key`, and `secret` example:

```json
{
    "host": "(us|eu)\\.xelis\\.luckypool\\.com",
    "key": "8f485301-e1e1-46a2-b5c4-0be884b9179f",
    "secret": "d373d733-d1a7-417f-84a3-3c363f8949bbddf62675-16f1-4e35-b6d4-7057e888b8b9"
}
```

`key` and `secret` are arbitrary values. NiceHash encodes `timestamp` with HMAC `key`/`secret` when `host` matches the pool URL.
`host` specification is a regular expression pattern.
The subscribe message sends a clear timestamp and an encoded timestamp. The pool follows the same procedure and compares hashes for equality.

#### HMAC code

```c++
std::string hash(const std::string &secret, const unsigned char *data, size_t data_size) {
    unsigned char *hash;
    unsigned int len = 64;
    hash = (unsigned char *) malloc(sizeof(unsigned char) * len);

    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, secret.c_str(), secret.length(), EVP_sha256(), NULL);
    HMAC_Update(ctx, data, data_size);
    HMAC_Final(ctx, hash, &len);
    HMAC_CTX_free(ctx);

    std::string hmac;
    hmac = utils::hex::bin2hex(hash, len);

    free(hash);

    return hmac;
}

std::string sign(const std::string &secret, const std::string &key, const std::string &time) {
    int data_size = key.length() + 1 + time.length();

    char *data = (char *) malloc(sizeof(char) * data_size);
    char *data_ptr = data;

    std::memcpy(data_ptr, key.c_str(), key.length());
    data_ptr += key.length();
 *data_ptr = '\0';
    data_ptr += 1;
    std::memcpy(data_ptr, time.c_str(), time.length());

    std::string x_hash = hash(secret, (const unsigned char *) data, data_size);

    free(data);

    return x_hash;
}
```

Pay attention to the `sign` function. `key` and `timestamp` are separated by `0` and encoded with the `secret`.


#### Contact
To include your key, secret, and host configuration in our production servers, please get in touch with info@nicehash.com.