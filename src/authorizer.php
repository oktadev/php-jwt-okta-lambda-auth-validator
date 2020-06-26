<?php

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;

static $signingKey = '';

function authorizer($data) {

	$type = $data['type'];
	$jwt = $data['authorizationToken'];
	$method = $data['methodArn'];

	$key_manager = OktaLambdaAuth\KeyManager::instance();
	$keys = $key_manager->getKeys();

	$decoded_token = null;
	$jwt_valid = false;

	foreach ( $keys as $key ) {
		try {
			$decoded_token = JWT::decode( $jwt, $key, array( 'RS256' ) );
			unset( $error );
			$jwt_valid = true;
		} catch ( ExpiredException | BeforeValidException $e) {
			$error = 'Token expired, or used before its validity';
			break;
		} catch ( SignatureInvalidException $e) {
			$error = 'Token not valid';
			continue;
		}
	}

	if ( ! $jwt_valid || ! $decoded_token) {
		$result = [
			'principalId' => 'unknown',
			'policyDocument' => [
				'Version' => '2012-10-17',
				'Statement' => [
					[
						'Action' => 'execute-api:Invoke',
						'Effect' => 'Deny',
						'Resource' => $method,
					]
				],
			]
		];

	} else {

		$result = [
			'principalId'    => $decoded_token->sub,
			'policyDocument' => [
				'Version'   => '2012-10-17',
				'Statement' => [
					[
						'Action'   => 'execute-api:Invoke',
						'Effect'   => 'Allow',
						'Resource' => $method,
					]
				],
			]
		];
	}

	return json_encode( $result );
}