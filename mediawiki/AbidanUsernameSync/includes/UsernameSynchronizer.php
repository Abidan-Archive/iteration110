<?php

namespace MediaWiki\Extension\AbidanUsernameSync;

use MediaWiki\RenameUser\RenameUserFactory;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserNameUtils;
use Psr\Log\LoggerInterface;
use Wikimedia\Rdbms\IDBAccessObject;

class UsernameSynchronizer {
	public function __construct(
		private UserFactory $userFactory,
		private UserNameUtils $userNameUtils,
		private RenameUserFactory $renameUserFactory,
		private LoggerInterface $logger
	) {
	}

	public function synchronize( int $userId, string $preferredName ): string {
		$user = $this->userFactory->newFromId( $userId );
		$user->load( IDBAccessObject::READ_LATEST );
		$oldName = $user->getName();
		$newName = $this->userNameUtils->getCanonical( $preferredName, UserNameUtils::RIGOR_CREATABLE );

		if ( $newName === false ) {
			$this->logger->warning( 'Archive username is invalid for MediaWiki; keeping existing name', [
				'userId' => $userId, 'preferredName' => $preferredName,
			] );
			return $oldName;
		}
		if ( $newName === $oldName ) {
			return $oldName;
		}

		$otherUser = $this->userFactory->newFromName( $newName );
		$otherUser->load( IDBAccessObject::READ_LATEST );
		if ( $otherUser->isRegistered() ) {
			$this->logger->warning( 'Archive username belongs to another wiki account; keeping existing name', [
				'userId' => $userId, 'newName' => $newName,
			] );
			return $oldName;
		}

		// Only this trusted OIDC flow may request a self-rename. Do not grant
		// renameuser to ordinary users or change user_name directly: core also
		// updates actors/contributions, caches, sessions, logs and user pages.
		$rename = $this->renameUserFactory->newRenameUser(
			$user,
			$user,
			$newName,
			'Synchronize username from Abidan Archive at OpenID Connect login',
			[ 'movePages' => true, 'suppressRedirect' => false ]
		);
		$status = $rename->renameUnsafe();
		if ( !$status->isGood() ) {
			$this->logger->warning( 'Archive username synchronization returned errors or page-move warnings', [
				'userId' => $userId, 'oldName' => $oldName, 'newName' => $newName,
				'errors' => $status->getErrors(),
			] );
		}

		// A page move can fail after the account itself has already been renamed.
		// Reload the actual name so authentication always uses the correct one.
		$reloadedUser = $this->userFactory->newFromId( $userId );
		$reloadedUser->load( IDBAccessObject::READ_LATEST );
		$actualName = $reloadedUser->getName();
		if ( $actualName !== $oldName ) {
			$this->logger->info( 'Synchronized Archive username', [
				'userId' => $userId, 'oldName' => $oldName, 'newName' => $actualName,
			] );
		}
		return $actualName;
	}
}
