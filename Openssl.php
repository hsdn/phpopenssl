<?php
/**************************************************************************
*	OpenSSL PHP Toolkit Library version 0.1.54-dev
*
*	(c) 2008-2013, Information Networks, Ltd. 
*	All Rights Reserved.
*
*	URL: http://www.hsdn.org 
*	Email: info@hsdn.org
*
*	Released under the terms and conditions of
*	the GNU General Public License (Version 2)
***************************************************************************

Features:
	* Generate RSA private keys in DER, NET or PEM formats
	* Convert RSA private keys to DER, NET, PEM formats
	* Create a Certificate requests in DER, NET or PEM formats
	* CA Signing a Certificate requests with OpenSSL Database (using config)
	* Create a Certificates in DER, NET or PEM formats
	* Convert Certificates to DER, NET or PEM formats
	* Verifying a Certificates
	* Get info from Certificates
	* Create Certificate Revocation Lists (CRL)
	* Revoke a Certificates on Certificate Revocation Lists
	* Convert CRL to DER and PEM formats
	* Concert Keys and Certificates to PKCS#12 format
	* Concert PKCS#12 format Keys and Certificates to PEM format

Requirements:
	* PHP Version 5.2.0 or higher (http://www.php.net)
	* OpenSSL Version 0.9.5 or higher (http://www.openssl.org)
	* PHP Extension: LDAP

***************************************************************************

Examples:
	$openssl = new OpenSSL;

	// Configeration
	$openssl->config = 'PKI/openssl.cnf'; 
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

	// Revoke certificate
	$openssl->crl_revoke(file_get_contents('PKI/certs/14.pem'), 'CApassword');
*/

class OpenSSL
{
	/*
	 * Path to OpenSSL program
	 *
	 * @access	public
	 */
	public $openssl = '/usr/local/bin/openssl';

	/*
	 * Path to temporally files directory (note: use `chmod 777')
	 *
	 * @access	public
	 */
	public $temp_dir = '/tmp';

	/*
	 * Path to OpenSSL configuration file
	 *
	 * @access	public
	 */
	public $config = '/etc/ssl/openssl.conf';

	/*
	 * Path to OpenSSL random file(s)
	 *
	 * @access	public
	 */
	public $random_file = FALSE;

	/*
	 * Debug mode (TRUE, FALSE)
	 *
	 * @access	public
	 */
	public $debug = TRUE;
	
	/*
	 * First returned error string
	 *
	 * @access	public
	 */
	public $error = FALSE;


	// --------------------------------------------------------------------
	//	RSA Private Key functions
	// --------------------------------------------------------------------

	/**
	 * Generate private key
	 *
	 * @see		http://www.openssl.org/docs/apps/genrsa.html
	 *
	 * @access	public
	 * @param	string	Output filename to write a key (use FALSE to rerurn is output)
	 * @param	int		Key length
	 * @param	string	Output file password
	 * @param	string	Output format [DER|NET|PEM]
	 * @param	string	Options encrypt the private key with the DES (note: only be used with PEM format) [des|des3|idea]
	 * @param	string	A file or files containing random data used to seed the random number generator, or an EGD socket
	 * @return	string|bool
	 */
	public function rsa_new($out = FALSE, $len = 2048, $passout = FALSE, $outform = FALSE, $alg = FALSE, $rand = FALSE)
	{
		putenv('RANDFILE='.$this->random_file);

		$outfile = $out;

		if (!$out)
		{
			$outfile = $this->temp_file();
		}

		if (!$passout)
		{
			$alg = FALSE;
		}

		$args = $this->build_args(array
		(
			'-'.$alg => TRUE, // md5, sha1, etc.
			'-passout pass:' => $passout,
			'-outform' => $outform,
			'-rand' => $rand,
			'-out' => $outfile,
			$len => TRUE, // len
		));

		$this->send_operation('genrsa', $args);

		if (!$out)
		{
			return $this->temp_export($outfile);
		}

		return !$this->error;
	}

	/**
	 * Export or convert a private key
	 *
	 * @see		http://www.openssl.org/docs/apps/rsa.html
	 *
	 * @access	public
	 * @param	string	Input data to read a key
	 * @param	string	Output filename to write a key (use FALSE to rerurn is output)
	 * @param	string	Input file password 
	 * @param	string	Output file password
	 * @param	string	Input format [DER|NET|PEM]
	 * @param	string	Output format [DER|NET|PEM]
	 * @param	string	Options encrypt the private key with the DES (note: only be used with PEM format) [des|des3|idea]
	 * @return	string|bool
	 */
	public function rsa_export($in, $out = FALSE, $passin = FALSE, $passout = FALSE, $inform = FALSE, $outform = FALSE, $alg = FALSE)
	{
		if (!$in)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $out;

		if (!$out)
		{
			$outfile = $this->temp_file();
		}

		$key = $this->temp_import($in);

		$args = $this->build_args(array
		(
			'-in' => $key,
			'-passin pass:' => $passin,
			'-passout pass:' => $passout,
			'-inform' => $inform,
			'-outform' => $outform,
			'-'.$alg => TRUE, // des, des3, etc.
			'-out' => $outfile,
		));

		$this->send_operation('rsa', $args);
		$this->temp_export($key);

		if (!$out)
		{
			return $this->temp_export($outfile);
		}

		return !$this->error;
	}

	// --------------------------------------------------------------------
	//	Request functions
	// --------------------------------------------------------------------

	/**
	 * Generate certificate request
	 *
	 * @see		http://www.openssl.org/docs/apps/req.html
	 *
	 * @access	public
	 * @param	string	Data to read the private key
	 * @param	string	Output filename to write a request (use FALSE to rerurn is output)
	 * @param	string	Subject name for new request (ex: Array('DC' => 'org', 'CN' => 'John Doe'))
	 * @param	string	Input file password
	 * @param	string	Number of days to certify the certificate
	 * @param	string	Format of the private key [PEM|DER]
	 * @param	string	Output format [DER|NET|PEM]
	 * @param	string	Configuration file section containing certificate extensions
	 * @param	bool	Outputs a self signed certificate instead of a certificate request
	 * @param	string	Configuration file to use
	 * @return	string|bool
	 */
	public function csr_new($key, $out = FALSE, $subj = FALSE, $passin = FALSE, $days = FALSE, $keyform = FALSE, $outform = FALSE, $extensions = FALSE, $x509 = FALSE, $config = FALSE)
	{
		if (!$key)
		{
			$this->message('key is not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $out;

		if (!$out)
		{
			$outfile = $this->temp_file();
		}

		if (!$config)
		{
			$config = $this->config;
		}
		
		$subject = '';

		foreach ($subj as $k => $v) 
		{
			$subject .= '/'.$k.'='.$v;
		}

		$key = $this->temp_import($key);

		$args = $this->build_args(array
		(
			'-new' => TRUE,
			'-subj' => $subject,
			'-key' => $key,
			'-x509' => $x509,
			'-passin pass:' => $passin,
			'-keyform' => $keyform,
			'-outform' => $outform,
			'-days' => $days,
			'-extensions' => $extensions,
			'-out' => $outfile,
		));
	
		$this->send_operation('req', $args);
		$this->temp_export($key);

		if (!$out)
		{
			return $this->temp_export($outfile);
		}

		return !$this->error;
	}

	/**
	 * Export or convert a certificate request
	 *
	 * @see		http://www.openssl.org/docs/apps/req.html
	 *
	 * @access	public
	 * @param	string	Input data to read a certificate request
	 * @param	string	Output filename to write a certificate request (use FALSE to terurn is output)
	 * @param	string	Input format [DER|NET|PEM]
	 * @param	string	Output format [DER|NET|PEM]
	 * @return	string|bool
	 */
	public function csr_export($in, $out = FALSE, $inform = FALSE, $outform = FALSE)
	{
		if (!$in)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $out;

		if (!$out)
		{
			$outfile = $this->temp_file();
		}

		$csr = $this->temp_import($in);

		$args = $this->build_args(array
		(
			'-in' => $csr,
			'-inform' => $inform,
			'-outform' => $outform,
			'-out' => $outfile,
		));

		$this->send_operation('req', $args);
		$this->temp_export($csr);

		if (!$out)
		{
			return $this->temp_export($outfile);
		}

		return !$this->error;
	}

	/**
	 * Parse request information
	 *
	 * @see		http://www.openssl.org/docs/apps/req.html
	 *
	 * @access	public
	 * @param	string	Input data to read a certificate request
	 * @param	string	Input format [DER|NET|PEM]
	 * @return	array|bool
	 */
	public function csr_parse($certificate, $inform = FALSE)
	{
		if (!$certificate)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $this->temp_file();
		$crt = $this->temp_import($certificate);

		$args = $this->build_args(array
		(
			'-noout' => TRUE,
			'-text' => TRUE,
			'-in' => $crt,
			'-inform' => $inform,
			'>>' => $outfile,
		));

		$this->send_operation('req', $args);
		$this->temp_export($crt);

		$retval = $this->temp_export($outfile);
		$lines = explode("\n", $retval);

		$array = $statement = array();

		foreach ($lines as $line)
		{
			preg_match('/^([\s]+)(.*)$/', $line, $spaces);

			if (!isset($spaces[1]) OR !isset($spaces[2]))
			{
				continue;
			}

			$space_len = strlen($spaces[1]);

			$statement[] = array($space_len, $spaces[2]);
		}

		$array = $this->parse_cert_statement($statement);

		if (!isset($array) OR !is_array($array) OR sizeof($array) < 1)
		{
			$this->message('parse error', __FUNCTION__);

			return FALSE;
		}

		$array['raw'] = $retval;

		return $array;
	}

	// --------------------------------------------------------------------
	//	Certificate functions
	// --------------------------------------------------------------------

	/**
	 * Signin a certificate (with Database)
	 *
	 * @see		http://www.openssl.org/docs/apps/ca.html
	 *
	 * @access	public
	 * @param	string	Input data containing a single certificate request 
	 * @param	string	Output filename to write a certificate (use FALSE to rerurn is output)
	 * @param	string	CA key password 
	 * @param	string	Configuration file section containing certificate extensions
	 * @param	string	Digest to use [md5|sha1|mdc2]
	 * @param	string	The number of days to certify the certificate for. 
	 * @param	string	Start date to be explicitly set (format YYMMDDHHMMSSZ)
	 * @param	string	Expiry date to be explicitly set (format YYMMDDHHMMSSZ)
	 * @param	bool	Create Self-signed certificate
	 * @param	string	Configuration file to use
	 * @return	string|bool
	 */
	public function csr_sign($in, $out = FALSE, $passin = FALSE, $extensions = FALSE, $alg = FALSE, $days = FALSE, $startdate = FALSE, $enddate = FALSE, $selfsign = FALSE, $config = FALSE)
	{
		putenv('RANDFILE='.$this->random_file);

		if (!$in)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $out;

		if (!$out)
		{
			$outfile = $this->temp_file();
		}

		if (!$config)
		{
			$config = $this->config;
		}

		$csr = $this->temp_import($in);

		$args = $this->build_args(array
		(
			'-config' => $config,
			'-selfsign' => $selfsign,
			'-in' => $csr,
			'-batch' => TRUE,
			'-extensions' => $extensions,
			'-passin pass:' => $passin,
			'-'.$alg => TRUE, // md5, sha1, etc.
			'-days' => $days,
			'-startdate' => $startdate,
			'-enddate' => $enddate,
			'-out' => $outfile,
		));

		$retval = $this->send_operation('ca', $args);

		$this->temp_export($csr);

		if (!$out)
		{
			return $this->temp_export($outfile);
		}

		if (!$this->error)
		{
			return $retval;
		}

		return !$this->error;
	}

	/**
	 * Verify certificate
	 *
	 * @see		http://www.openssl.org/docs/apps/verify.html
	 *
	 * @access	public
	 * @param	string	CA Certificate and CRL bundle data (note: includes Intermediate CA's is exists!)
	 * @param	string	Certificate data to verify
	 * @param	string	If this option is not specified, verify will not consider certificate purpose during chain verification
	 *						Currently accepted uses are: sslclient, sslserver, nssslserver, smimesign, smimeencrypt
	 * @param	string	Enable policy processing and add arg to the user-initial-policy-set (see RFC5280)
	 * @param	string	Enables certificate policy processing
	 * @param	string	Set policy variable require-explicit-policy (see RFC5280)
	 * @param	string	Checks end entity certificate validity by attempting to look up a valid CRL
	 * @param	string	Checks the validity of all certificates in the chain by attempting to look up valid CRLs
	 * @param	string	For strict X.509 compliance, disable non-compliant workarounds for broken certificates
	 * @return	string
	 */
	public function crt_verify($CA, $certificate, $purpose = FALSE, $policy = FALSE, $policy_check = FALSE, $explicit_policy = FALSE, $crl_check = FALSE, $crl_check_all = FALSE, $x509_strict = FALSE)
	{
		if (!$CA OR !$certificate)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$CAfile = $this->temp_import($CA, 'ca');
		$crt = $this->temp_import($certificate, 'crt');

		$args = $this->build_args(array
		(
			'-CAfile' => $CAfile,
			'-purpose' => $purpose,
			'-policy' => $policy,
			'-policy_check' => $policy_check,
			'-explicit_policy' => $explicit_policy,
			'-crl_check' => $crl_check,
			'-crl_check_all' => $crl_check_all,
			'-x509_strict' => $x509_strict,
			$crt => TRUE, // file neme
		));

		$result = $this->send_operation('verify', $args);

		$this->temp_export($CAfile);
		$this->temp_export($crt);

		return (strpos($result, ': OK') !== FALSE); // @see $this->error for details
	}

	/**
	 * Export or convert a certificate
	 *
	 * @see		http://www.openssl.org/docs/apps/x509.html
	 *
	 * @access	public
	 * @param	string	Input data to read a certificate
	 * @param	string	Output filename to write a certificate request (use FALSE to terurn is output)
	 * @param	string	Input format [DER|NET|PEM]
	 * @param	string	Output format [DER|NET|PEM]
	 * @param	string	Digest to use [md2|md5|sha1|mdc2]
	 * @param	bool	Full details are output
	 * @return	string|bool
	 */
	public function crt_export($in, $out = FALSE, $inform = FALSE, $outform = FALSE, $alg = FALSE, $text = TRUE)
	{
		if (!$in)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $out;

		if (!$out)
		{
			$outfile = $this->temp_file();
		}

		$crt = $this->temp_import($in);

		$args = $this->build_args(array
		(
			'-in' => $crt,
			'-inform' => $inform,
			'-outform' => $outform,
			'-text' => $text,
			'-'.$alg => TRUE, // md5, sha1, etc.
			'-out' => $outfile,
		));

		$this->send_operation('x509', $args);
		$this->temp_export($crt);

		if (!$out)
		{
			return $this->temp_export($outfile);
		}

		return !$this->error;
	}

	/**
	 * Parse certificate information
	 *
	 * @see		http://www.openssl.org/docs/apps/x509.html
	 *
	 * @access	public
	 * @param	string	Input data to read a certificate
	 * @param	string	Input format [DER|PEM]
	 * @return	array|bool
	 */
	public function crt_parse($certificate, $inform = FALSE)
	{
		if (!$certificate)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $this->temp_file();
		$crt = $this->temp_import($certificate);

		$args = $this->build_args(array
		(
			'-noout' => TRUE,
			'-text' => TRUE,
			'-purpose' => TRUE,
			'-in' => $crt,
			'-inform' => $inform,
			'>>' => $outfile,
		));

		$this->send_operation('x509', $args);
		$this->temp_export($crt);

		$retval = $this->temp_export($outfile);

		$retval = str_replace(
			str_repeat(' ', 4).'Signature Algorithm:', 
			str_repeat(' ', 8).'Signature Algorithm:', 
			$retval);
		$lines = explode("\n", $retval);

		$statement = array();

		foreach ($lines as $line)
		{
			preg_match('/^([\s]+)(.*)$/', $line, $spaces);

			if (!isset($spaces[1]) OR !isset($spaces[2]))
			{
				continue;
			}

			$space_len = strlen($spaces[1]);

			$statement[] = array($space_len, $spaces[2]);
		}

		$array = $this->parse_cert_statement($statement);

		foreach ($lines as $value)
		{
			preg_match("/^([^\:]+) \: (Yes|No)/sU", $value, $purposes);
			
			if (isset($purposes[1]) AND isset($purposes[2]))
			{
				$purposes[1] = str_replace(' ', '_', strtolower($purposes[1]));

				$array['purposes'][$purposes[1]] = ($purposes[2] == 'Yes');
			}
		}

		if (!isset($array) OR !is_array($array) OR sizeof($array) < 1)
		{
			$this->message('parse error', __FUNCTION__);

			return FALSE;
		}

		$array['raw'] = $retval;

		return $array;
	}

	// --------------------------------------------------------------------
	//	CRL functions
	// --------------------------------------------------------------------

	/**
	 * Generate CRL
	 *
	 * @see		http://www.openssl.org/docs/apps/crl.html
	 *
	 * @access	public
	 * @param	string	Output filename to write a CRL (use FALSE to rerurn is output)
	 * @param	string	CA key password 
	 * @param	string	Configuration file section containing CRL extensions
	 * @param	string	Number of days before the next CRL is due
	 * @param	string	Configuration file to use
	 * @return	string|bool
	 */
	public function crl_new($out = FALSE, $passin = FALSE, $crlexts = FALSE, $crldays = FALSE, $config = FALSE)
	{
		$outfile = $out;

		if (!$out)
		{
			$outfile = $this->temp_file();
		}

		if (!$config)
		{
			$config = $this->config;
		}

		$args = $this->build_args(array
		(
			'-gencrl' => TRUE,
			'-config' => $config,
			'-passin pass:' => $passin,
			'-crlexts' => $crlexts,
			'-crldays' => $crldays,
			'-out' => $outfile,
		));

		$this->send_operation('ca', $args);
		
		if (!$out)
		{
			return $this->temp_export($outfile);
		}

		return !$this->error;
	}

	/**
	 * Revoke certificate
	 *
	 * @see		http://www.openssl.org/docs/apps/crl.html
	 *
	 * @access	public
	 * @param	string	Certificate data to revoke
	 * @param	string	CA key password 
	 * @param	string	Revocation reason (where reason is one of: unspecified, keyCompromise, CACompromise, 
	 *						affiliationChanged, superseded,  cessationOfOperation or removeFromCRL)
	 * @param	string	Revocation reason to keyCompromise and the compromise time (format YYYYMMDDHHMMSSZ)
	 * @param	string	crl_compromise except the revocation reason is set to CACompromise (format YYYYMMDDHHMMSSZ)
	 * @param	string	Configuration file to use
	 * @return	string|bool
	 */
	public function crl_revoke($revoke, $passin = FALSE, $reason = FALSE, $crl_compromise = FALSE, $crl_CA_compromise = FALSE, $config = FALSE)
	{
		if (!$revoke)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		if (!$config)
		{
			$config = $this->config;
		}

		$crt = $this->temp_import($revoke);

		$args = $this->build_args(array
		(
			'-gencrl' => TRUE,
			'-config' => $config,
			'-revoke' => $crt,
			'-passin pass:' => $passin,
			'-crl_reason' => $reason,
			'-crl_compromise' => $crl_compromise,
			'-crl_CA_compromise' => $crl_CA_compromise,
		));

		$this->send_operation('ca', $args);
		$this->temp_export($crt);

		return !$this->error;
	}

	/**
	 * Export or convert a CRL
	 *
	 * @see		http://www.openssl.org/docs/apps/crl.html
	 *
	 * @access	public
	 * @param	string	Input data to read a CRL
	 * @param	string	Output filename to write a CRL (use FALSE to rerurn is output)
	 * @param	string	Input format [DER|PEM]
	 * @param	string	Output format [DER|PEM]
	 * @param	bool	Print out the CRL in text form.
	 * @param	bool	Don't output the encoded version of the CRL.
	 * @param	bool	Output a hash of the issuer name. This can be use to lookup CRLs in a directory by issuer name.
	 * @param	bool	Output the issuer name.
	 * @param	bool	Output the lastUpdate field.
	 * @param	bool	Output the nextUpdate field.
	 * @param	string	Verify the signature on a CRL by looking CA data
	 * @return	string|bool
	 */
	public function crl_export($in, $out = FALSE, $inform = FALSE, $outform = FALSE, $text = FALSE, $hash = FALSE, $issuer = FALSE, $lastupdate = FALSE, $nextupdate = FALSE, $CA = FALSE)
	{
		if (!$in)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $out;

		if (!$out)
		{
			$outfile = $this->temp_file();
		}

		$crl = $this->temp_import($in, 'crl');
		$CAfile = $CA = FALSE;

		if ($CA)
		{
			$CAfile = $this->temp_import($CA, 'ca');
		}

		$args = $this->build_args(array
		(
			'-in' => $crl,
			'-inform' => $inform,
			'-outform' => $outform,
			'-out' => $outfile,
			'-text' => $text, 
			'-hash' => $hash, 
			'-issuer' => $issuer,
			'-lastupdate' => $lastupdate,
			'-nextupdate' => $nextupdate,
			'-CAfile' => $CAfile,
		));

		$this->send_operation('crl', $args);
		$this->temp_export($crl);
		
		if ($CA)
		{
			$this->temp_export($CAfile);
		}

		if (!$out)
		{
			return $this->temp_export($outfile);
		}

		return !$this->error;
	}

	/**
	 * Parse CRL
	 *
	 * @see		http://www.openssl.org/docs/apps/crl.html
	 *
	 * @access	public
	 * @param	string	Input data to read a CRL
	 * @param	string	Input format [DER|PEM]
	 * @return	string|bool
	 */
	public function crl_parse($crl, $inform = FALSE)
	{
		if (!$crl)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $this->temp_file();

		$crl = $this->temp_import($crl, 'crl');

		$args = $this->build_args(array
		(
			'-noout' => TRUE,
			'-text' => TRUE,
			'-in' => $crl,
			'-inform' => $inform,
			'>>' => $outfile,
		));

		$this->send_operation('crl', $args);
		$this->temp_export($crl);

		$retval = $this->temp_export($outfile);
		$lines = explode("\n", $retval);

		$statement = array();

		foreach ($lines as $line)
		{
			preg_match('/^([\s]+)(.*)$/', $line, $spaces);

			if (!isset($spaces[1]) OR !isset($spaces[2]))
			{
				continue;
			}

			$space_len = strlen($spaces[1]);

			$statement[] = array($space_len, $spaces[2]);
		}

		$array = $this->parse_cert_statement($statement);

		if (!isset($array) OR !is_array($array) OR sizeof($array) < 1)
		{
			$this->message('parse error', __FUNCTION__);

			return FALSE;
		}

		$array['raw'] = $retval;

		return $array;
	}

	// --------------------------------------------------------------------
	//	PKCS#12 functions
	// --------------------------------------------------------------------

	/**
	 * Convert PKCS#12 to PEM
	 *
	 * @see		http://www.openssl.org/docs/apps/pkcs12.html#PARSING_OPTIONS
	 *
	 * @access	public
	 * @param	string	Input PKCS#12 data to read
	 * @param	string	Output filename to write a certificates and keys in PEM format
	 * @param	string	The PKCS#12 file password source
	 * @param	string	Pass phrase source to encrypt any outputed private keys with.
	 * @param	bool	Don't encrypt the private keys at all.
	 * @param	string	Encrypt private keys before outputting [des|des3|idea|aes128|aes192|aes256|camellia128|camellia192|camellia256]
	 * @param	bool	No certificates at all will be output.
	 * @param	bool	No private keys will be output.
	 * @param	bool	Output additional information about the PKCS#12 file structure, algorithms used and iteration counts.
	 * @return	string|bool
	 */
	public function pkcs12_export($in, $out = FALSE, $passin = FALSE, $passout = FALSE, $nodes = FALSE, $alg = FALSE, $nocerts = FALSE, $nokeys = FALSE, $info = FALSE)
	{
		if (!$in)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $out;

		if (!$out)
		{
			$outfile = $this->temp_file();
		}

		if (!$passout)
		{
			$alg = FALSE;
		}

		$pkcs12 = $this->temp_import($in);

		$args = $this->build_args(array
		(
			'-in' => $pkcs12,
			'-passin pass:' => $passin,
			'-passout pass:' => $passout,
			'-nodes' => $nodes,
			'-'.$alg => TRUE, // des, des3 etc.
			'-nocerts' => $nocerts,
			'-nokeys' => $nokeys,
			'-info' => $info,
			'-out' => $outfile,
		));

		$this->send_operation('pkcs12', $args);
		$this->temp_export($pkcs12);

		if (!$out)
		{
			return $this->temp_export($outfile);
		}

		return !$this->error;
	}

	/**
	 * Convert PEM to PKCS#12
	 *
	 * @see		http://www.openssl.org/docs/apps/pkcs12.html#FILE_CREATION_OPTIONS
	 *
	 * @access	public
	 * @param	string	Input PEM format data to read
	 * @param	string	Output filename to write a PKCS#12
	 * @param	string	CA Certificate data
	 * @param	string	Private key data
	 * @param	string	Pass phrase source to decrypt any input private keys with
	 * @param	string	The PKCS#12 output file password source.
	 * @param	string	This specifies the `friendly name' for the certificate and private key
	 * @param	string	This specifies the `friendly name' for other certificates
	 * @param	bool	Include the entire certificate chain of the user certificate (note: not use for CA)
	 * @param	bool	Encrypt the certificate using triple DES
	 * @param	string	Algorithm used to encrypt the private key to be selected
	 * @param	string	Algorithm used to encrypt the certificates to be selected
	 *						Any PKCS#5 v1.5 or PKCS#12 PBE algorithm name can be used (e.g.: PBE-SHA1-RC2-40).
	 * @return	string|bool
	 */
	public function pkcs12_import($in, $out = FALSE, $CA = FALSE, $inkey = FALSE, $passin = FALSE, $passout = FALSE, $name = FALSE, $caname = FALSE, $chain = FALSE, $descert = FALSE, $keypbe = FALSE, $certpbe = FALSE)
	{
		if (!$in)
		{
			$this->message('input data not defined', __FUNCTION__);

			return FALSE;
		}

		$outfile = $out;

		if (!$out)
		{
			$outfile = $this->temp_file();
		}

		$pem = $this->temp_import($in, 'pem');
		$CAfile = $this->temp_import($CA, 'ca');
		$inkey = $this->temp_import($inkey, 'inkey');

		if (!$passout)
		{
			$passout = TRUE;
		}

		$args = $this->build_args(array
		(
			'-export' => TRUE,
			'-in' => $pem,
			'-CAfile' => $CAfile,
			'-inkey' => $inkey,
			'-passin pass:' => $passin,
			'-passout pass:' => $passout,
			'-name' => $name,
			'-caname' => $caname,
			'-chain' => $chain,
			'-keypbe' => $keypbe,
			'-certpbe' => $certpbe,
			'-out' => $outfile,
		));

		$this->send_operation('pkcs12', $args);
		$this->temp_export($pem);
		$this->temp_export($CAfile);
		$this->temp_export($inkey);

		if (!$out)
		{
			return $this->temp_export($outfile);
		}

		return !$this->error;
	}

	// --------------------------------------------------------------------
	//	Private functions
	// --------------------------------------------------------------------

	/**
	 * Process OpenSSL operation
	 *
	 * @access	private
	 * @param	string
	 * @param	array
	 * @return	bool
	 */
	private function send_operation($op, $args)
	{
		array_unshift($args, $op);

		$params = implode(' ', $args);

		$openssl = $this->openssl_command($params);

		if ($this->debug) 
		{
			if (!$openssl)
			{
				$openssl = TRUE;
			}

			$this->message($openssl, $params, FALSE);	
		}

		// Skip Notice
		$openssl = str_replace("unable to write 'random state'", '', $openssl);

		if (preg_match("/(error|invalid|unknown option|to be supplied)/is", $openssl) OR
			preg_match("/(usage:)/", $openssl))
		{
			$this->message($openssl, reset($args));
			$this->message(NULL, $args);

			return FALSE;
		}

		return $openssl;
	}

	/**
	 * Send OpenSSL command
	 *
	 * @access	private
	 * @param	array
	 * @return	string
	 */
	private function openssl_command($args)
	{
		// Replace badchars
		$args = str_replace(array('|', '^', '&&', '\\', "\n", "\r"), '', $args);

		if (!$fp = @popen($this->openssl.' '.$args.' 2>&1', 'r'))
		{
			$this->message('runtime error', __FUNCTION__);

			return FALSE;
		}

		$buffer = '';

		while (!feof($fp))
		{
			$buffer .= fgets($fp, 4096);
		}

		pclose($fp);

		return trim($buffer);
	}

	/**
	 * Build command arguments
	 *
	 * @access	private
	 * @param	array
	 * @return	array
	 */
	private function build_args($args)
	{
		$build = array();

		foreach ($args as $name => $value)
		{
			$name = trim($name);

			if ($name != '' AND $name != '-' AND $value != '' AND $value !== FALSE)
			{
				$value = ($value === TRUE) ? '' : $value;

				// Replace badchars
				$value = str_replace(array(' -', '>', '<', '"', "'", ','), '', $value);

				if (strpos($value, ' ') !== FALSE)
				{
					$value = '"'.$value.'"';
				}

				if (strpos($name, ':') !== FALSE)
				{
					$build[] = trim($name.$value);
				}
				else
				{
					$build[] = trim($name.' '.$value);
				}
			}
		}

		return $build;
	}

	/**
	 * Write temp file
	 *
	 * @access	private
	 * @param	string
	 * @param	string
	 * @return	string|bool
	 */
	private function temp_import($data, $suffix = '')
	{
		if ($data == '')
		{
			return FALSE;
		}

		$file = $this->temp_file($suffix);

		if (!@file_put_contents($file, $data))
		{
			$this->message('write error: '.$file, __FUNCTION__);

			return FALSE;
		}

		return $file;
	}

	/**
	 * Read temp file
	 *
	 * @access	private
	 * @param	string
	 * @return	string|bool
	 */
	private function temp_export($file)
	{
		if (!file_exists($file))
		{
			$this->message('not exists: '.$file, __FUNCTION__);

			return FALSE;
		}

		$data = @file_get_contents($file);

		if (!unlink($file))
		{
			$this->message('delete error: '.$file, __FUNCTION__);

			return FALSE;
		}

		return $data;
	}

	/**
	 * Get temp file name
	 *
	 * @access	private
	 * @param	string
	 * @return	string
	 */
	private function temp_file($suffix = '')
	{
		return $this->temp_dir.'/'.$this->session().$suffix;
	}

	/**
	 * Get session name
	 *
	 * @access	private
	 * @return	string
	 */
	private function session()
	{
		$env = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : mt_rand();

		return sha1(microtime().$env);
	}

	/**
	 * Parse OpenSSL config file
	 *
	 * @access	private
	 * @param	string
	 * @return	array|bool
	 */
	private function config_parse($config)
	{
		$config = str_replace("\r\n", "\n", $config);
		$config_lines = explode("\n", $config);

		$config_array = array();

		foreach ($config_lines as $val)
		{
			if (!preg_match("/^#/i", $val))
			{
				if ($comments = strpos($val, '#'))
				{
					$cval  = substr($val, 0, $comments);
				}

				$config_array[] = $val;
			}
		}

		$config = implode("\n", $config_array);
		
		preg_match("/^(.*)\[/isU", $config, $extra);
		preg_match_all("/\[(.*)\].*\n/isU", $config, $sections);
		
		$contents = preg_split("/\[.*\].*\n/", $config);
		$extra_lines = explode("\n", $extra[1]);

		$array = array();

		if (is_array($extra_lines))
		{
			foreach ($extra_lines as $val)
			{
				$line = explode('=', $val);

				$key = trim($line[0]);
				$val = trim($line[1]);

				if ($key AND $val)
				{
					$array[0][$key] = $val;
				}
			}
		}

		foreach ($sections[1] as $skey => $sval)
		{
			$contents_lines = explode("\n", $contents[$skey + 1]);

			foreach ($contents_lines as $cval)
			{
				$line = explode('=', $cval);

				$key = trim($line[0]);
				$val = trim($line[1]);
				$sval = trim($sval);

				if ($key AND $val)
				{
					$array[$sval][$key] = $val;
				}
			}
		}

		if (!is_array($array) OR sizeof($array) < 1)
		{
			$this->message('structure error', __FUNCTION__);

			return FALSE;
		}

		return $array;
	}

	/**
	 * Build OpenSSL config file
	 *
	 * @access	private
	 * @param	array
	 * @return	string|bool
	 */
	private function config_build($array)
	{
		if (!is_array($array) OR sizeof($array) < 1)
		{
			$this->message('parse error', __FUNCTION__);

			return FALSE;
		}

		$return = '';

		foreach ($array as $key => $val)
		{
			if ($key)
			{
				$return .= '[ '.$key." ]\n";
			}
			foreach ($val as $key => $val)
			{
				$return .= $key.' = '.$val."\n";
			}

			$return .= "\n";
		}

		$return = trim($return);

		if ($return == '')
		{
			$this->message('build error', __FUNCTION__);

			return FALSE;
		}

		return $return;
	}

	/**
	 * Parse certificate statement child
	 *
	 * @access	private
	 * @param	array
	 * @return	array
	 */
	private function parse_cert_statement($statement)
	{
		$return = $childs = array();

		$first_len = 0;
		$name = '';

		foreach ($statement as $component)
		{
			list($len, $data) = $component;

			$data = trim($data);

			if ($name != '' AND $first_len < $len)
			{
				$childs[$name]['#'][] = array($len, $data);
			}
			else
			{
				$data_exp = preg_split("/(\:\s|\:$)/", $data, 2);
				$name = str_replace(array(' ', '(', ')'), array('_', '', ''), strtolower($data_exp[0]));
				$first_len = $len;

				if (isset($data_exp[1]) AND $data_exp[1] != '')
				{
					if ($name == 'subject' OR $name == 'issuer')
					{
						$childs[$name]['@'][] = $z = $this->parse_cert_subject($data_exp[1]);
					}
					else
					{
						$childs[$name]['@'][] = $data_exp[1];
					}
				}
				else
				{
					$childs['*']['@'][] = $data;
				}
			}
		}

		if (isset($childs['*']['@']))
		{
			$string = implode("\n", $childs['*']['@']);

			$string_exp = str_split($string);

			if (end($string_exp) != ':')
			{
				$childs['*']['@'] =	$string;
			}
			else
			{
				unset($childs['*']['@']);
			}
		}

		foreach ($childs as $child_key => $child_data)
		{
			if (isset($child_data['@']))
			{
				$return[$child_key]['@'] = $child_data['@'];
			}

			if (isset($child_data['#']))
			{
				$statement = $this->parse_cert_statement($child_data['#']);

				$return[$child_key]['#'] = $statement;
			}
		}

		return $return;
	}

	/**
	 * Parse certificate subject
	 *
	 * @access	private
	 * @param	string
	 * @return	array
	 */
	private function parse_cert_subject($subject)
	{
		$return = array();

		$delim = "#(,\s|\/)([a-z0-9.]+)\=#si";
		$subject = ', '.$subject; // for get first element

		if (!preg_match_all($delim, $subject, $names, PREG_PATTERN_ORDER))
		{
			return FALSE;
		}

		$values = preg_split($delim, $subject);

		foreach ($names[2] as $index => $name)
		{
			$index++;

			if (!isset($values[$index]))
			{
				continue;
			}

			$return[] = array
			(
				'name' => $name,
				'value' => trim($values[$index], ', '),
			);
		}

		return $return;
	}

	/**
	 * Print debug message and error string
	 *
	 * @access	private
	 * @param	string
	 * @param	string
	 * @param	bool
	 * @return	void
	 */
	private function message($var, $function, $bold = TRUE)
	{
		if (!$var)
		{
			return;
		}

		if (!$this->error AND $bold)
		{
			if (preg_match("|Error([^\n]+)|s", $var, $ret))
			{
				$var = $ret[1];
			}
			else if (preg_match('|\:error:(.*)\:\/|', $var, $ret))
			{
				$exp = explode(':', $ret[1]);
				$var = end($exp);
			}
			else if (preg_match('|error (.*)$|s', $var, $ret))
			{
				$exp = explode(':', $ret[1]);
				$var = end($exp);
			}
			else if (preg_match("/^(.*)usage:/s", $var, $ret))
			{
				$var = $ret[1];
			}
			else if (preg_match("|unable to([^\n]+)|s", $var, $ret))
			{
				$var = 'unable to'.$ret[1];
			}
			else if (preg_match("/(The .* field needed to be supplied and was missing)/s", $var, $ret))
			{
				$var = $ret[1];
			}
			else if (preg_match("/^([^\n]+)/s", $var, $ret))
			{
				$var = $ret[1];
			}

			$var = empty($var) ? 'unknown error' : lcfirst($var);

			$this->error = 'Error('.$function.'): '.$var;
		}

		if (!$this->debug) 
		{
			return;
		}

		if ($bold)
		{
			echo '<font style="color:red">'.nl2br($this->error)."</font><br />\n";
		}
		else
		{
			$function = preg_replace("/pass\:([^\s]+)/is", 'pass:<font style="color:darkred">replaced</font>', $function);

			echo '<font style="color:blue">Info('.$function.')</font><br />'.
				 (($var !== TRUE) ? '<font style="color:darkblue">'.nl2br($var).'</font><br />' : '')."\n";
		}
	}
}

/* End of file */