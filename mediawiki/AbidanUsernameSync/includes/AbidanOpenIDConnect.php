<?php

namespace MediaWiki\Extension\AbidanUsernameSync;

use MediaWiki\Extension\OpenIDConnect\OpenIDConnect;
use MediaWiki\MediaWikiServices;
use MediaWiki\User\UserIdentityValue;

class AbidanOpenIDConnect extends OpenIDConnect {
	public function authenticate(
		?int &$id,
		?string &$username,
		?string &$realname,
		?string &$email,
		?string &$errorMessage
	): bool {
		if ( !parent::authenticate( $id, $username, $realname, $email, $errorMessage ) ) {
			return false;
		}

		// New accounts already use preferred_username. Existing accounts have been
		// matched by (issuer, subject), never by the mutable Archive username.
		if ( $id !== null ) {
			$claims = $this->getAttributes( new UserIdentityValue( $id, $username ) );
			$preferredName = $claims['preferred_username'] ?? null;
			if ( is_string( $preferredName ) ) {
				$username = MediaWikiServices::getInstance()
					->getService( 'AbidanUsernameSynchronizer' )
					->synchronize( $id, $preferredName );
			}
		}

		return true;
	}
}
