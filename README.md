# report-openssl-ml-dsa-key-usage-cert-ext

## C reproducer

```
$ ./compile.sh
$ ./reproducer
OpenSSL version: OpenSSL 4.1.0-dev

keyUsage: Digital Signature, Key Encipherment, Data Encipherment, Key Agreement, Encipher Only, Decipher Only

Certificate was signed successfully with prohibited keyUsage values.
OpenSSL should have rejected this per RFC 9881 Section 5.
```

## Ruby OpenSSL (openssl gem)

```
$ ruby reproducer.rb
OpenSSL version: OpenSSL 4.1.0-dev
Ruby OpenSSL version: 4.0.2

keyUsage: Digital Signature, Key Encipherment, Data Encipherment, Key Agreement, Encipher Only, Decipher Only

Certificate was signed successfully with prohibited keyUsage values.
OpenSSL should have rejected this per RFC 9881 Section 5.
```
