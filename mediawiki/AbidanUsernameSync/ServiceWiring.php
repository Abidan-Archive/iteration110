<?php

use MediaWiki\Extension\AbidanUsernameSync\UsernameSynchronizer;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\MediaWikiServices;

return [
	'AbidanUsernameSynchronizer' => static function ( MediaWikiServices $services ): UsernameSynchronizer {
		return new UsernameSynchronizer(
			$services->getUserFactory(),
			$services->getUserNameUtils(),
			$services->getRenameUserFactory(),
			LoggerFactory::getInstance( 'AbidanUsernameSync' )
		);
	},
];
