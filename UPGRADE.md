This file describes the steps you will need to make when upgrading this bundle.

# From 2.0 to 3.0

  - ES signing algorithms are now supported
  - Token validity verification now uses a configured leeway seconds value, which by default is 300
    - Configurable with `token_leeway_seconds` client option
    - The `iat` claim is now also taken into account
  - Additional cache has been added for JWK results caching
    - Cache can be disabled by setting the `jwks_cache_time` client option to `null`
  - Internal cache keys have been updated
  - `OidcJwtHelper` has been rewritten: if you were not calling this class yourself, you should be fine
    - Only a new `verifyTokens` function is now available which combines the old `verifyJwtSignature` and `verifyJwtClaims` methods
    - `decodeJwt` and `getIdTokenClaims` are no longer available, but you can get a decoded token object with `JwtHelper::parseToken()`
  - Support for `phpseclib/phpseclib` 2 has been dropped
  - The `getJwktUri` method typo in `OidcClient` has been fixed, it is now `getJwksUri`
  - The `OidcJwtHelper` is no longer passed to the `OidcAuthenticator` instance

# From 2.0 to 2.1

The following has changed:

  - Constructor parameters of a couple of classes (should all be managed by the bundle dependency injection)
    - Drenso\OidcBundle\OidcClient
    - Drenso\OidcBundle\OidcJwtHelper
    - Drenso\OidcBundle\Security\OidcAuthenticator
  - Session information is now stored per configured client, using a dedicated class
  - Remember me support has been added (disabled by default)

# From 1.x to 2.x

As 2.x is a major rewrite which actually leverages the Symfony configuration component, you will need to remove most of
your previous configuration.

### What hasn't changed?

The `oidc` key and its options remain the same in your firewall configuration 🎉

### Configuration to remove

Remove the `OidcClient` registration from your `services.yaml` which passed the configuration values:

```yaml
parameters:
  oidc.well_known_url: '%env(OIDC_WELL_KNOWN)%'
  oidc.client_id: '%env(OIDC_CLIENT_ID)%'
  oidc.client_secret: "%env(string:key:oidc:json:file:resolve:SECRETS_FILE)%"

services:
  Drenso\OidcBundle\OidcClient:
    arguments:
      $wellKnownUrl: '%oidc.well_known_url%'
      $clientId: '%oidc.client_id%'
      $clientSecret: '%oidc.client_secret%'
```

Also, remove the security listeners:

```php
services:
  security.authentication.provider.oidc:
    class: Drenso\OidcBundle\Security\Authentication\Provider\OidcProvider
    arguments:
      - ''
      - '@security.user_checker'
      - '@security.token_storage'
      - '@logger'

  security.authentication.listener.oidc:
    class: Drenso\OidcBundle\Security\Firewall\OidcListener
    arguments:
      - '@security.token_storage'
      - '@security.authentication.manager'
      - '@security.authentication.session_strategy'
      - '@security.http_utils'
      - ''
      - ''
      - ''
      - { }
      - '@logger'
      - '@Drenso\OidcBundle\OidcClient'
```

Remove the OidcFactory from the `Kernel.php` build method:

```php
  /**
   * @param ContainerBuilder $container
   */
  protected function build(ContainerBuilder $container)
  {
    // Register the OIDC factory
    $extension = $container->getExtension('security');
    assert($extension instanceof SecurityExtension);
    $extension->addSecurityListenerFactory(new OidcFactory());
  }
```

### Configuration to update

First, make sure to let Flex install/update the recipe:

```
composer sync-recipes drenso/symfony-oidc-bundle --force
```

This will add the required configuration. Now, simply set a value for the newly added environment variables, or update
the configuration file with your variables/parameters.

### Implementations to update

First, you will need to update your User Provider to implement the new methods from the `OidcUserProviderInterface`, as
the `loadUserByToken` is no longer used. Instead, now two methods need to be implemented:

- `ensureUserExists(string $userIdentifier, OidcUserData $userData)`: Implement this method to bootstrap a new account
  using the data available from the passed `OidcUserData` object. The identifier is a configurable property from the
  user data, which defaults to `sub`. If the account cannot be bootstrapped, authentication will be impossible as the
  User Provider will not be capable of retrieving the user.
- `loadOidcUser(string $userIdentifier): UserInterface`: Implement this method to retrieve the user based on the
  identifier. We use a dedicated method instead of Symfony's default `loadUserByIdentifier` to allow you to detect where
  the login is coming from, without the need of creating a dedicated user provider. If the OIDC user identifiers are
  unique, a forward to the `loadUserByIdentifier` should be sufficient.

Secondly, it is no longer required to manually clear the security session when starting the OIDC authorization. You can remove the following lines from you redirect controller (if you had them):

```php
// Remove errors from state
$session->remove(Security::AUTHENTICATION_ERROR);
$session->remove(Security::LAST_USERNAME);
```

### login_check route

The `login_check` route (see https://github.com/Drenso/symfony-oidc/issues/5) is no longer needed, we now default to the `/login_check` path as is normally used by the Symfony form login method as well.

### Caching

By default, this bundle now caches the well known response for an hour. The cache time is configurable, but note that caching will only work when `symfony/cache` is available in your container.

### Breaking changes

Most breaking changes are related to classes having been renamed or removed. If you did not rely on any of the
internals, these changes should not be problematic for you.

- `Drenso\OidcBundle\OidcTokens` has moved to `Drenso\OidcBundle\Model\OidcTokens`. The functionality has not changed.
- `Drenso\OidcBundle\Security\Authentication\Token\OidcToken` has been replaced with two classes:
  - `Drenso\OidcBundle\Model\OidcUserData`: Contains the user data as retrieved from the OIDC provider 
  - `Drenso\OidcBundle\Security\Token\OidcToken`: Contains the same data as the old `OidcToken`, but it is required to first retrieve the new `OidcUserData` value before being able to access the user data. Use `getAuthData` and `getUserData` on the token when you require them. 
  - The `getUsername` method is removed.
  - It is no longer possible to override the retrieved OIDC data with the `setAuthData` and `setUserData` methods, but you can still do it using the token attributes (not recommended).
- `Drenso\OidcBundle\OidcClient`: No longer returns `NULL` in case of missing query parameters of invalid state, instead it throws an `OidcException`.
  - The `retrieveUserInfo` method now return the user data wrapped in a `Drenso\OidcBundle\Model\OidcUserData` for easy access.
  - It is no longer possible to autowire the client with the `OidcClient` class, you will need to use the `OidcClientInterface`
- `Drenso\OidcBundle\Security\Authentication\Provider\OidcProvider` is no longer available
- `Drenso\OidcBundle\Security\EntryPoint\OidcEntryPoint` is no longer available
- `Drenso\OidcBundle\Security\Firewall\OidcListener` is no longer available
- `Drenso\OidcBundle\Security\Exception\OidcUsernameNotFoundException` has been renamed to `Drenso\OidcBundle\Security\Exception\OidcUserNotFoundException`
- `Drenso\OidcBundle\Security\UserProvider\OidcUserProviderInterface` has been changed, see above.

We've also annotated all methods using their actual return types, and removed doc block definitions where possible.

### Missing something?

Feel free to open an issue!
