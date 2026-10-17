<?php

// Run against a disposable SQLite wiki named username_sync_test; see README.md.
require_once getenv( 'MW_INSTALL_PATH' ) . '/maintenance/Maintenance.php';

use MediaWiki\Content\WikitextContent;
use Jumbojett\OpenIDConnectClient;
use MediaWiki\Extension\AbidanUsernameSync\AbidanOpenIDConnect;
use MediaWiki\Extension\AbidanUsernameSync\UsernameSynchronizer;
use MediaWiki\Extension\PluggableAuth\PluggableAuthLogin;
use MediaWiki\Maintenance\Maintenance;
use MediaWiki\Revision\SlotRecord;
use MediaWiki\Registration\ExtensionRegistry;
use Psr\Log\AbstractLogger;

class TestAbidanUsernameSync extends Maintenance {
	private int $checks = 0;

	private function check( bool $condition, string $message ): void {
		if ( !$condition ) {
			$this->fatalError( $message );
		}
		$this->checks++;
	}

	public function execute() {
		$config = $this->getConfig();
		if ( $config->get( 'DBtype' ) !== 'sqlite' || $config->get( 'DBname' ) !== 'username_sync_test' ) {
			$this->fatalError( 'This integration test requires a disposable SQLite username_sync_test database.' );
		}
		$services = $this->getServiceContainer();
		$dbw = $services->getConnectionProvider()->getPrimaryDatabase();
		$suffix = bin2hex( random_bytes( 4 ) );
		$oldName = 'Archive old ' . $suffix;
		$newName = 'Archive new ' . $suffix;
		$user = $services->getUserFactory()->newFromName( $oldName );
		$this->check( $user->addToDatabase()->isOK(), 'Could not create test user' );
		$userId = $user->getId();
		$actorId = $user->getActorId();
		$store = $services->getService( 'OpenIDConnectStore' );
		$subject = 'archive-user-' . $suffix;
		$store->saveExtraAttributes( $userId, $subject, 'http://localhost:8000' );

		$services->getAuthManager()->getRequest()->setSessionData(
			PluggableAuthLogin::AUTHENTICATIONPLUGINNAME_SESSION_KEY, 'pluggableauthlogin0'
		);
		$plugin = $services->getService( 'PluggableAuthFactory' )->getInstance();
		$this->check( $plugin instanceof AbidanOpenIDConnect, 'Custom authentication plugin was not instantiated' );

		foreach ( [ NS_USER => 'Profile content', NS_USER_TALK => 'Talk content' ] as $namespace => $text ) {
			$title = $services->getTitleFactory()->makeTitle( $namespace, $oldName );
			$page = $services->getWikiPageFactory()->newFromTitle( $title );
			$status = $page->doUserEditContent( new WikitextContent( $text ), $user, 'Test edit' );
			$this->check( $status->isOK(), 'Could not create test user page' );
		}
		$services->getDBLoadBalancerFactory()->commitPrimaryChanges( __METHOD__ );

		$logger = new class extends AbstractLogger {
			public array $records = [];
			public function log( $level, $message, array $context = [] ): void {
				$this->records[] = [ $level, $message, $context ];
			}
		};
		$sync = new UsernameSynchronizer(
			$services->getUserFactory(), $services->getUserNameUtils(),
			$services->getRenameUserFactory(), $logger
		);
		$this->check( $sync->synchronize( $userId, $newName ) === $newName, 'Username did not synchronize' );
		$this->check( $services->getUserFactory()->newFromName( $newName )->getId() === $userId, 'User ID changed' );
		[ $linkedId, $linkedName ] = $store->findUser( $subject, 'http://localhost:8000' );
		$this->check( (int)$linkedId === $userId && $linkedName === $newName, 'OIDC link did not survive rename' );
		$actorName = $dbw->newSelectQueryBuilder()->select( 'actor_name' )->from( 'actor' )
			->where( [ 'actor_id' => $actorId, 'actor_user' => $userId ] )->caller( __METHOD__ )->fetchField();
		$this->check( $actorName === $newName, 'Contribution actor was not renamed' );

		foreach ( [ NS_USER => 'Profile content', NS_USER_TALK => 'Talk content' ] as $namespace => $text ) {
			$title = $services->getTitleFactory()->makeTitle( $namespace, $newName );
			$revision = $services->getRevisionLookup()->getRevisionByTitle( $title );
			$this->check( $revision !== null && $revision->getContent( SlotRecord::MAIN )->getText() === $text,
				'User or talk page did not move with its content' );
			$this->check( $revision->getUser()->getId() === $userId, 'Edit ownership changed' );
			$oldTitle = $services->getTitleFactory()->makeTitle( $namespace, $oldName );
			$oldRevision = $services->getRevisionLookup()->getRevisionByTitle( $oldTitle );
			$this->check( $oldRevision !== null && $oldRevision->getContent( SlotRecord::MAIN )->isRedirect(),
				'Old user page did not retain a redirect' );
		}

		$recordCount = count( $logger->records );
		$this->check( $sync->synchronize( $userId, str_replace( ' ', '_', lcfirst( $newName ) ) ) === $newName,
			'Canonical spelling caused an unnecessary rename' );
		$this->check( count( $logger->records ) === $recordCount, 'Unchanged name attempted another rename' );
		$this->check( $sync->synchronize( $userId, 'Invalid#name' ) === $newName, 'Invalid username changed account' );
		$this->check( end( $logger->records )[0] === 'warning', 'Invalid name was not logged' );

		$other = $services->getUserFactory()->newFromName( 'Archive occupied ' . $suffix );
		$this->check( $other->addToDatabase()->isOK(), 'Could not create collision account' );
		$this->check( $sync->synchronize( $userId, $other->getName() ) === $newName, 'Collision renamed the account' );
		$this->check( end( $logger->records )[0] === 'warning', 'Collision was not logged' );
		$this->check( $services->getUserFactory()->newFromName( $other->getName() )->getId() === $other->getId(),
			'Collision affected another account' );
		$this->check( $sync->synchronize( $userId, $oldName ) === $oldName, 'Could not rename back to original name' );
		[ $linkedId, $linkedName ] = $store->findUser( $subject, 'http://localhost:8000' );
		$this->check( (int)$linkedId === $userId && $linkedName === $oldName, 'Identity changed after second rename' );

		// Exercise the complete adapter with a client supplying already-verified
		// claims. Network/signature verification remains the upstream client's job.
		$client = new class extends OpenIDConnectClient {
			public bool $authenticated = true;
			public array $claims = [];
			public function authenticate(): bool {
				return $this->authenticated;
			}
			public function getVerifiedClaims( string $attribute = null ) {
				return $attribute === null ? (object)$this->claims : ( $this->claims[$attribute] ?? null );
			}
			public function getIdTokenPayload() {
				return (object)$this->claims;
			}
			public function getAccessTokenPayload() {
				return null;
			}
		};
		$client->claims = [
			'sub' => $subject, 'preferred_username' => $newName,
			'name' => $newName, 'email' => 'sync-test@example.invalid',
		];
		$spec = ExtensionRegistry::getInstance()->getAttribute( 'PluggableAuthAbidanOpenIDConnect' );
		$args = array_map( static fn ( $name ) => $name === 'OpenIDConnectClient' ? $client : $services->getService( $name ),
			$spec['services'] );
		$authenticatedPlugin = new AbidanOpenIDConnect( ...$args );
		$authenticatedPlugin->init( 'Abidan Archive', $config->get( 'PluggableAuth_Config' )['Abidan Archive'] );
		$id = $name = $realname = $email = $error = null;
		$this->check( $authenticatedPlugin->authenticate( $id, $name, $realname, $email, $error ),
			'Adapter rejected successful authentication' );
		$this->check( (int)$id === $userId && $name === $newName,
			'Adapter did not rename the subject-linked account: ' . json_encode( [ $id, $name, $userId, $newName ] ) );

		// Use the real PluggableAuth group pipeline, including OIDC attribute
		// normalization and core group storage, for promotion and revocation.
		$groupManager = $services->getUserGroupManager();
		$groupManager->addUserToGroup( $user, 'bot' );
		$runner = $services->getService( 'PluggableAuth.GroupProcessorRunner' );
		foreach ( [
			[ [ 'wiki_admin' ], true, false ],
			[ [ 'wiki_moderator' ], false, true ],
			[ [ 'wiki_admin', 'wiki_moderator' ], true, true ],
			[ [], false, false ],
			[ [ 'admin', 'mod', 'sysop', 'bureaucrat' ], false, false ],
		] as [ $roles, $admin, $moderator ] ) {
			$client->claims['wiki_roles'] = $roles;
			$id = $name = $realname = $email = $error = null;
			$this->check( $authenticatedPlugin->authenticate( $id, $name, $realname, $email, $error ),
				'Role-change login failed' );
			$runner->run( $user, $authenticatedPlugin );
			$groups = $groupManager->getUserGroups( $user );
			$this->check( in_array( 'sysop', $groups ) === $admin, 'Incorrect administrator membership' );
			$this->check( in_array( 'moderator', $groups ) === $moderator, 'Incorrect moderator membership' );
			$this->check( in_array( 'bot', $groups ), 'Group sync removed an unrelated local group' );
		}
		$client->claims['wiki_roles'] = [ 'wiki_admin', 'wiki_moderator' ];
		$authenticatedPlugin->authenticate( $id, $name, $realname, $email, $error );
		$runner->run( $user, $authenticatedPlugin );
		unset( $client->claims['wiki_roles'] );
		$authenticatedPlugin->authenticate( $id, $name, $realname, $email, $error );
		$runner->run( $user, $authenticatedPlugin );
		$this->check( !array_intersect( [ 'sysop', 'moderator' ], $groupManager->getUserGroups( $user ) ),
			'Missing role claim retained privileged groups' );
		$client->claims['wiki_roles'] = [ 'wiki_moderator' ];
		$authenticatedPlugin->authenticate( $id, $name, $realname, $email, $error );
		$runner->run( $user, $authenticatedPlugin );
		$rights = $services->getPermissionManager()->getUserPermissions( $user );
		foreach ( [ 'block', 'delete', 'undelete', 'protect', 'rollback', 'patrol' ] as $right ) {
			$this->check( in_array( $right, $rights ), 'Moderator missing right: ' . $right );
		}
		$this->check( !array_intersect( [ 'userrights', 'editinterface', 'editsitejs', 'editsitecss' ], $rights ),
			'Moderator received administrator-only rights' );

		$client->authenticated = false;
		$client->claims['preferred_username'] = $oldName;
		$id = $name = $realname = $email = $error = null;
		$this->check( !$authenticatedPlugin->authenticate( $id, $name, $realname, $email, $error ),
			'Adapter accepted failed authentication' );
		$this->check( $services->getUserFactory()->newFromName( $newName )->getId() === $userId,
			'Failed authentication renamed the account' );

		$client->authenticated = true;
		$client->claims['sub'] = 'unlinked-' . $suffix;
		$client->claims['preferred_username'] = 'Archive first login ' . $suffix;
		$client->claims['wiki_roles'] = [ 'wiki_admin' ];
		$id = $name = $realname = $email = $error = null;
		$this->check( $authenticatedPlugin->authenticate( $id, $name, $realname, $email, $error ),
			'Adapter broke first-login authentication' );
		$this->check( $id === null && $name === $client->claims['preferred_username'],
			'Adapter changed upstream account-creation behavior' );
		$firstUser = $services->getUserFactory()->newFromName( $name );
		$this->check( $firstUser->addToDatabase()->isOK(), 'Could not provision first-login user' );
		$authenticatedPlugin->saveExtraAttributes( $firstUser->getId() );
		$runner->run( $firstUser, $authenticatedPlugin );
		$this->check( in_array( 'sysop', $groupManager->getUserGroups( $firstUser ) ),
			'First-login administrator did not receive permissions' );
		$this->output( "Passed {$this->checks} username and role synchronization integration checks.\n" );
	}
}

$maintClass = TestAbidanUsernameSync::class;
require_once RUN_MAINTENANCE_IF_MAIN;
