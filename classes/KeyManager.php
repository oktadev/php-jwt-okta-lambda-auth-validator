<?php

namespace OktaLambdaAuth;

use CoderCat\JWKToPEM\JWKConverter;

class KeyManager {

	// Static class
	protected static $instance;

	private $base_url;

	/**
	 * @return KeyManager
	 */
	public static function instance() {
		if ( static::$instance === null ) {
			static::$instance = new static();
		}

		return static::$instance;
	}

	private $keys;
	private $valid_until;

	public function __construct() {
		$this->keys = [];
		$this->valid_until = 0;
	}

	public function updateKeys() {

		$server = Config::OKTA_SERVER_HOSTNAME;
		$url = 'https://' . $server . '/oauth2/default/v1/keys?client_id=' . Config::OKTA_APP_CLIENT_ID;

		$curl = curl_init();

		$headers = [];

		curl_setopt_array( $curl, array(
			CURLOPT_URL            => $url,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_ENCODING       => "",
			CURLOPT_MAXREDIRS      => 10,
			CURLOPT_TIMEOUT        => 120,
			CURLOPT_FOLLOWLOCATION => true,
			CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
			CURLOPT_HEADERFUNCTION => static function( $c, $header ) use ( &$headers ) {
				$len = strlen($header);
				$header = explode(':', $header, 2);
				if (count($header) < 2) // ignore invalid headers
					return $len;

				$headers[strtolower( trim( $header[0] ) )][] = trim( $header[1] );

				return $len;
			}
		) );

		$response_json = curl_exec( $curl );
		curl_close($curl);

		$response = json_decode( $response_json );

		if ( isset( $response->errorCode ) ) {
			// Error
			fwrite( STDERR, 'Error retrieving JWT-signing key: ' . $response->errorSummary );
			return false;
		}

		// Let's convert the received keys into PEM format, usable from the key verifier library
		$keys = $response->keys;
		$pem_keys = [];
		$jwkConverter = new JWKConverter();

		foreach ( $keys as $key) {
			$pem_keys[] = $jwkConverter->toPEM( (array) $key );
		}

		if ( count( $pem_keys ) ) {
			$this->keys = $pem_keys;
			$this->valid_until = strtotime( $headers['expires'][0] );
		}

		return $this->keys;
	}

	public function getKeys() {
		if ( count( $this->keys ) && $this->valid_until > time() ) {
			return $this->keys;
		}
		return $this->updateKeys();
	}

	public function getValidUntil() {
		return date('Y-m-d H:i:s e', $this->valid_until );
	}

}