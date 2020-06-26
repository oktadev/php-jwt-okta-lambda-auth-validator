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

		// Build the URL from Okta that we'll use to retrieve the current set of signing keys
		$server = Config::OKTA_SERVER_HOSTNAME;
		$url = 'https://' . $server . '/oauth2/default/v1/keys?client_id=' . Config::OKTA_APP_CLIENT_ID;

		$client = new \GuzzleHttp\Client();
		$query_response = $client->get( $url );

		$response = json_decode( (string) $query_response->getBody() );

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
			// Save both the keys and their expiring moment for future use
			$this->keys = $pem_keys;
			$this->valid_until = strtotime( $query_response->getHeader('expires')[0] );
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