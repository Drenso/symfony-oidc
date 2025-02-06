<?php declare(strict_types = 1);

$ignoreErrors = [];
$ignoreErrors[] = [
	'message' => '#^Method Drenso\\\\OidcBundle\\\\Model\\\\OidcUserData\\:\\:getUserDataArray\\(\\) return type has no value type specified in iterable type array\\.$#',
	'identifier' => 'missingType.iterableValue',
	'count' => 1,
	'path' => __DIR__ . '/src/Model/OidcUserData.php',
];
$ignoreErrors[] = [
	'message' => '#^Access to constant AUTHENTICATION_ERROR on an unknown class Symfony\\\\Component\\\\Security\\\\Core\\\\Security\\.$#',
	'identifier' => 'class.notFound',
	'count' => 1,
	'path' => __DIR__ . '/src/OidcClient.php',
];
$ignoreErrors[] = [
	'message' => '#^Access to constant LAST_USERNAME on an unknown class Symfony\\\\Component\\\\Security\\\\Core\\\\Security\\.$#',
	'identifier' => 'class.notFound',
	'count' => 1,
	'path' => __DIR__ . '/src/OidcClient.php',
];
$ignoreErrors[] = [
	'message' => '#^Access to undefined constant Symfony\\\\Bundle\\\\SecurityBundle\\\\Security\\:\\:AUTHENTICATION_ERROR\\.$#',
	'identifier' => 'classConstant.notFound',
	'count' => 1,
	'path' => __DIR__ . '/src/OidcClient.php',
];
$ignoreErrors[] = [
	'message' => '#^Access to undefined constant Symfony\\\\Bundle\\\\SecurityBundle\\\\Security\\:\\:LAST_USERNAME\\.$#',
	'identifier' => 'classConstant.notFound',
	'count' => 1,
	'path' => __DIR__ . '/src/OidcClient.php',
];
$ignoreErrors[] = [
	'message' => '#^Parameter \\#2 \\$option of function curl_setopt expects int, string given\\.$#',
	'identifier' => 'argument.type',
	'count' => 1,
	'path' => __DIR__ . '/src/OidcUrlFetcher.php',
];
$ignoreErrors[] = [
	'message' => '#^Method Drenso\\\\OidcBundle\\\\Security\\\\Factory\\\\OidcFactory\\:\\:createAuthProvider\\(\\) has parameter \\$config with no value type specified in iterable type array\\.$#',
	'identifier' => 'missingType.iterableValue',
	'count' => 1,
	'path' => __DIR__ . '/src/Security/Factory/OidcFactory.php',
];
$ignoreErrors[] = [
	'message' => '#^Parameter \\$passport of method Drenso\\\\OidcBundle\\\\Security\\\\OidcAuthenticator\\:\\:createAuthenticatedToken\\(\\) has invalid type Symfony\\\\Component\\\\Security\\\\Http\\\\Authenticator\\\\Passport\\\\PassportInterface\\.$#',
	'identifier' => 'class.notFound',
	'count' => 1,
	'path' => __DIR__ . '/src/Security/OidcAuthenticator.php',
];

return ['parameters' => ['ignoreErrors' => $ignoreErrors]];
