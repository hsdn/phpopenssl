# OpenSSL PHP Toolkit Library

PHP library to work with the functions of OpenSSL. Unlike the standard functionality available in the PHP openssl module (http://php.net/manual/en/ref.openssl.php), this library supports the standard OpenSSL database of certificates. Perfect for organizing a full OpenSSL PKI functionality in PHP. See tutorial http://pki-tutorial.readthedocs.org/en/latest/simple/index.html about the PKI functions in OpenSSL.

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

### Examples (for a PKI functions):

``` php
<?php
require_once 'src/OpenSSL.php';

$openssl = new OpenSSL;

// Database configurations 
// See http://pki-tutorial.readthedocs.org/en/latest/simple/index.html#configuration-files
$openssl->config   = 'PKI/openssl.cnf'; 
$openssl->temp_dir = 'PKI/tmp';

// Create private key
$key = $openssl->rsa_new(FALSE, 1024, 'password', FALSE, 'des3');
	
// Create signing request
$subj = array
(
	'C' => 'RU', 
	'ST' => 'Moscow', 
	'L' => 'Moscow Region', 
	'O' => 'My Company', 
	'OU' => 'Company Unit', 
	'CN' => 'Real Name', 
	'emailAddress' => 'my@email.com'
);

$csr = $openssl->csr_new($key, FALSE, $subj, 'password');

// Sign a certificate request
echo $openssl->csr_sign($csr, FALSE, 'CApassword', 'client_cert');

// Create CRL
$openssl->crl_new(FALSE, 'CApassword');

// Revoke the certificate
$openssl->crl_revoke(file_get_contents('PKI/certs/14.pem'), 'CApassword');
```
