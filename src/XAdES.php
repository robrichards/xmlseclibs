<?php

/**
 * Copyright (c) 2021 and later years, Bill Seddon <bill.seddon@lyquidity.com>.
 * All rights reserved.
 *
 * MIT License 
 * 
 * Allows a document to be signed using one of the XAdES forms up to XAdES-T.
 * https://www.w3.org/TR/XAdES/
 * 
 * Builds on XMLSecurityDSig to sign and verify Xml documents using the XmlDSig 
 * extensions which take it into the domain of non-repudiation by defining XML 
 * formats for advanced electronic signatures that remain valid over long periods 
 * and are compliant with the European "Directive 1999/93/EC
 */

namespace lyquidity\xmldsig;

use \RobRichards\XMLSecLibs\XMLSecurityDSig;
use \RobRichards\XMLSecLibs\XMLSecEnc;

/**
 */
class XAdES extends XMLSecurityDSig
{
	const NamespaceUrl = "http://uri.etsi.org/01903/v1.3.2#";
	// Xades specification requires "http://uri.etsi.org/01903/v1.1.1#SignedProperties" but the receiving party currently does not accept this value
	const ReferenceType = "http://uri.etsi.org/01903#SignedProperties";
	const SignedPropertiesId = "signed-properties";
	const SignatureRootId = "signature-root";

	/**
	 * Extends the core XmlDSig verification to also verify <Object/QualifyingProperties/SignedProperties>
	 *
	 * @param string $signatureFile This might be a standalone signature file
	 * @param string $certificateFile (optional) If provided it is an absolute path to the relevant .crt file or a path relative to the signature file
	 * @return bool
	 */
	static function verifyXAdES( $signatureFile, $certificateFile = null )
	{
		if ( ! file_exists( $signatureFile ) )
		{
			echo "Signature file does not exist";
			return false;
		}

		try
		{
			// Load the XML to be signed
			$signatureDoc = new \DOMDocument();
			$signatureDoc->load( $signatureFile );

			// Assume this is true for now
			$dataDoc = null;

			$signedPropertiesQuery = "/ds:Signature/ds:Object/xa:QualifyingProperties/xa:SignedProperties[@Id=\"" . self::SignedPropertiesId . "\"]";
			$objRefQuery = "./xa:SignedDataObjectProperties/xa:DataObjectFormat[@ObjectReference]/@ObjectReference";

			$xpath = new \DOMXPath( $signatureDoc );
			$xpath->registerNamespace( 'ds', XMLSecurityDSig::XMLDSIGNS );
			$xpath->registerNamespace( 'xa', self::NamespaceUrl );
			$signedProperties = $xpath->evaluate( $signedPropertiesQuery );

			if ( count( $signedProperties ) )
			{
				$objRef = $xpath->evaluate( $objRefQuery, $signedProperties[0] );

				if ( count( $objRef ) )
				{
					// The should be an external file.  Look for it in the <Reference> with @Id $objRef
					$fileQuery = "/ds:Signature/ds:SignedInfo/ds:Reference[@Id=\"" . ltrim( $objRef[0]->value, '#' ) . "\"]/@URI";
					$fileRef = $xpath->evaluate( $fileQuery );

					if ( ! count( $fileRef ) )
						throw new \Exception("The object reference file '$objRef' cannot be located within the signature.");

					// Create a uri to the file. For some reason PHP reports 'file:/...' not 
					// 'file://...' for the document URI which is invalid so needs fixing
					$dataFile = self::resolve_path( preg_replace( '!file:/([a-z]:)!i', "file://$1", $signatureDoc->documentURI ), urldecode( $fileRef[0]->value ) );

					// There is an external file
					$dataDoc = new \DOMDocument();
					$dataDoc->load( $dataFile );
				}
			}

			// Create a new Security object
			$XAdES  = new XAdES();

			$objDSig = $XAdES->locateSignature( $signatureDoc );
			if ( ! $objDSig )
			{
				throw new \Exception("Cannot locate Signature Node");
			}
			$XAdES->canonicalizeSignedInfo();
			
			$return = $XAdES->validateReference( $dataDoc? $dataDoc->documentElement : null );

			if (! $return) {
				throw new \Exception("Reference Validation Failed");
			}
			
			$objKey = $XAdES->locateKey();
			if ( ! $objKey ) 
			{
				throw new \Exception("We have no idea about the key");
			}
			$key = NULL;
			
			$objKeyInfo = XMLSecEnc::staticLocateKeyInfo( $objKey, $objDSig );

			if ( ! $objKeyInfo->key && empty( $key ) && $certificateFile ) 
			{
				// Load the certificate
				$certificateFile = self::resolve_path( $signatureDoc->documentURI, $certificateFile );
				if ( ! file_exists( $certificateFile ) )
				{
					throw new \Exception( "Certificate file does not exist" );
				}
				$objKey->loadKey( $certificateFile, true );
			}

			if ( $XAdES->verify( $objKey ) === 1 )
			{
				echo "XAdES signature validated!\n";
			} 
			else
			{
				throw new \Exception( "The XAdES signature is not valid: it may have been tampered with." );
			}

			$certQuery = "./xa:SignedSignatureProperties/xa:SigningCertificate/xa:Cert";
			$serialNumberQuery = $certQuery . "/xa:IssuerSerial/ds:X509SerialNumber";
			$issuerQuery = $certQuery . "/xa:IssuerSerial/ds:X509IssuerName";

			// Grab the serial number from the certificate used to compare it with the number stored in the signed properties
			$certificateData = $objKeyInfo->getCertificateData();
			$gmp = gmp_import( hex2bin( $certificateData['serialNumberHex'] ) );
			$serialNumber = gmp_strval( $gmp );

			// Get the serial number from the signed properties
			$serialNumberElement = $xpath->query( $serialNumberQuery, $signedProperties[0] );
			if ( ! count( $serialNumberElement ) )
			{
				throw new \Exception('The certificate serial number does not exist in the signature');
			}
			else if ( $serialNumber != $serialNumberElement[0]->textContent )
			{
				throw new \Exception('The certificate serial number in the signature does not match the certificate serial number');
			}

			// Grab the issuer from the certificate used to compare it with the number stored in the signed properties
			/** @var string[] $issuer */
			$issuer = $certificateData['issuer'];

			$issuerElement = $xpath->query( $issuerQuery, $signedProperties[0] );
			if ( ! count( $issuerElement ) )
			{
				throw new \Exception('The certificate issuer does not exist in the signature');
			}

			$certIssuer = array_reduce( explode( ',', $issuerElement[0]->textContent ), function( $carry, $part )
			{
				list( $code, $value ) = explode( '=', trim( $part ) );
				// $value .= "x";
				$carry[ $code ] = $value;
				// OpenSSL and the .NET Framework seem to use different codes for some OIDs
				if ( $code == "emailAddress" ) $carry['E'] = $value;
				if ( $code == "E" ) $carry['emailAddress'] = $value;
				if ( $code == "ST" ) $carry['S'] = $value;
				if ( $code == "S" ) $carry['ST'] = $value;

				return $carry;
			}, array() );

			// Are there any matches?  There should be.
			$matched = array_intersect_key( $certIssuer, $issuer );
			// Make sure the values are the same
			foreach ( $matched as $code => $value )
			{
				if ( $certIssuer[ $code ] == $issuer[ $code ] ) continue;
				$matched = false;
				break;
			}
			if ( ! $matched )
			{
				throw new \Exception('The certificate issuer in the signature does not match the certificate issuer number');
			}

			// If there is a policy and a policy hash
			$sigPolicyQuery = "./xa:SignedSignatureProperties/xa:SignaturePolicyIdentifier/xa:SignaturePolicyId";
			$policyIdentifierQuery = $sigPolicyQuery . "/xa:SigPolicyId/xa:Identifier";
			$policyDigestQuery = $sigPolicyQuery . "/xa:SigPolicyHash/ds:DigestValue";
			$policyMethodQuery = $sigPolicyQuery . "/xa:SigPolicyHash/ds:DigestMethod/@Algorithm";

			$policyIdentifier = $xpath->query( $policyIdentifierQuery, $signedProperties[0] );
			if ( count( $policyIdentifier ) )
			{
				$policyIdentifier = $policyIdentifier[0]->textContent;

				// Is there a digest?
				$policyDigest = $xpath->query( $policyDigestQuery, $signedProperties[0] );
				if ( count( $policyDigest ) )
				{
					$policyDigest = $policyDigest[0]->textContent;

					// Gat the hash method
					$policymethod = $xpath->query( $policyMethodQuery, $signedProperties[0] );
					$policymethod = count( $policymethod ) ? $policymethod[0]->textContent : XMLSecurityDSig::SHA256;

					$xml = file_get_contents( $XAdES->getPolicyDocument( $policyIdentifier ) );
					$doc = new \DOMDocument();
					$doc->loadXML( $xml );
				
					// Create a new Security object 
					// $objXMLSecDSig  = new XMLSecurityDSig();
					$output = $XAdES->processTransforms( $doc->documentElement, $doc->documentElement, false );
					$digest = $XAdES->calculateDigest( $policymethod, $output );
								
					$match = $policyDigest == $digest;
				}
			}

			echo "\n";
		}
		catch( \Exception $ex )
		{
			print $ex->getMessage();
		}

	}

	/**
	 * Its expected this will be overridden in a descendent class
	 * @var string $policyIdentifier
	 * @return string A path or URL to the policy document
	 */
	public function getPolicyDocument( $policyIdentifier )
	{
		return "http://nltaxonomie.nl/sbr/signature_policy_schema/v2.0/SBR-signature-policy-v2.0.xml";
	}

	/**
	 * Used to compute an absolute path for a resource ($target) with respect to a source.
	 * For example, the presentation linkbase file will be specified as relative to the
	 * location of the host schema.
	 * @param string $source The resource for the source
	 * @param string $target The resource for the target
	 * @return string
	 */
	public static function resolve_path( $source, $target )
	{
		// $target = urldecode( $target );

		$source = str_replace( '\\', '/', $source );
		// Remove any // instances as they confuse the path normalizer but take care to
		// not to remove ://
		$offset = 0;
		while ( true )
		{
			$pos = strpos( $source, "//", $offset );
			if ( $pos === false ) break;
			$offset = $pos + 2;
			// Ignore :// (eg https://)
			if ( $pos > 0 && $source[ $pos-1 ] == ":" ) continue;
			$source = str_replace( "//", "/", $source );
			$offset--;
		}

		// Using the extension to determine if the source is a file or directory reference is problematic unless it is always terminated with a /
		// This is because the source directory path may include a period such as x:/myroot/some.dir-in-a-path/
		$source = self::endsWith( $source, '/' ) || pathinfo( $source, PATHINFO_EXTENSION ) === "" //  || is_dir( $source )
			? $source
			: pathinfo( $source, PATHINFO_DIRNAME );

		$sourceIsUrl = filter_var( rawurlencode( $source ), FILTER_VALIDATE_URL );
		$targetIsUrl = filter_var( rawurlencode( $target ), FILTER_VALIDATE_URL );

		// Absolute
		if ( $target && ( filter_var( $target, FILTER_VALIDATE_URL ) || ( strtoupper( substr( PHP_OS, 0, 3 ) ) === 'WIN' && strlen( $target ) > 1 && ( $target[1] === ':' || substr( $target, 0, 2 ) === '\\\\' ) ) ) )
			$path = $target;

		// Relative to root
		elseif ( $target && ( $target[0] === '/' || $target[0] === '\\' ) )
		{
			$root = self::get_schema_root( $source );
			$path = $root . $target;
		}
		// Relative to source
		else
		{
			if ( self::endsWith( $source, ":" ) ) $source .= "/";
			$path =  $source . ( substr( $source, -1 ) == '/' ? '' : '/' ) . $target;
		}

		// Process the components
		// BMS 2018-06-06 By ignoring a leading slash the effect is to create relative paths on linux
		//				  However, its been done to handle http://xxx sources.  But this is not necessary (see below)
		$parts = explode( '/', $path );
		$safe = array();
		foreach ( $parts as $idx => $part )
		{
			// if ( empty( $part ) || ( '.' === $part ) )
			if ( '.' === $part )
			{
				continue;
			}
			elseif ( '..' === $part )
			{
				array_pop( $safe );
				continue;
			}
			else
			{
				$safe[] = $part;
			}
		}

		// BMS 2108-06-06 See above
		return implode( '/', $safe );

		// Return the "clean" path
		return $sourceIsUrl || $targetIsUrl
			? str_replace( ':/', '://', implode( '/', $safe ) )
			: implode( '/', $safe );
	}

	/**
	 * Find out if $haystack ends with $needle
	 * @param string $haystack
	 * @param string $needle
	 * @return boolean
	 */
	public static function endsWith( $haystack, $needle )
	{
		$strlen = strlen( $haystack );
		$testlen = strlen( $needle );
		if ( $testlen > $strlen ) return false;
		return substr_compare( $haystack, $needle, $strlen - $testlen, $testlen ) === 0;
	}

	/**
	 * Used by resolve_path to obtain the root element of a uri or file path.
	 * This is necessary because a schema or linkbase uri may be absolute but without a host.
	 *
	 * @param string The file
	 * @return string The root
	 */
	private static function get_schema_root( $file )
	{
		if ( filter_var( $file, FILTER_VALIDATE_URL ) === false )
		{
			// my else codes goes
			if ( strtoupper( substr( PHP_OS, 0, 3 ) ) === 'WIN' )
			{
				// First case is c:\
				if ( strlen( $file ) > 1 && substr( $file, 1, 1 ) === ":" )
					$root = "{$file[0]}:";
				// Second case is a volume
				elseif ( strlen( $file ) > 1 && substr( $file, 0, 2 ) === "\\\\" )
				{
					$pos = strpos( $file, '\\', 2 );

					if ( $pos === false )
						$root = $file;
					else
						$root = substr( $file, 0, $pos );
				}
				// The catch all is that no root is provided
				else
					$root = pathinfo( $file, PATHINFO_EXTENSION ) === ""
						? $file
						: pathinfo( $file, PATHINFO_DIRNAME );
			}
		}
		else
		{
			$components = parse_url( $file );
			$root = "{$components['scheme']}://{$components['host']}";
		}

		return $root;
	}
}