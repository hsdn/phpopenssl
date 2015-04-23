# OpenSSL PHP Toolkit Library

PHP library to work with the functions of OpenSSL. Unlike the the standard functionality available in the PHP openssl module (http://php.net/manual/en/ref.openssl.php), this library supports the standard OpenSSL database of certificates.

### Features:
- Generate RSA private keys in DER, NET or PEM formats
- Convert RSA private keys to DER, NET, PEM formats
- Create a Certificate requests in DER, NET or PEM formats
- CA Signing a Certificate requests with OpenSSL Database (using config)
- Create a Certificates in DER, NET or PEM formats
- Convert Certificates to DER, NET or PEM formats
- Verifying a Certificates
- Get info from Certificates
- Create Certificate Revocation Lists (CRL)
- Revoke a Certificates on Certificate Revocation Lists
- Convert CRL to DER and PEM formats
- Concert Keys and Certificates to PKCS#12 format
- Concert PKCS#12 format Keys and Certificates to PEM format

### Requirements:
- PHP version 5.2.0 or higher (http://www.php.net)
- OpenSSL version 0.9.5 or higher (http://www.openssl.org)
- LDAP PHP extension
