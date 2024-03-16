# Symfony OIDC bundle

This bundle can be used to add OIDC support to any Symfony application. We have only tested it with
SURFconext OIDC, but it should work with any OIDC provider!

Many thanks to https://github.com/jumbojett/OpenID-Connect-PHP for the implementation which this bundle uses although it has been modified to fix within an object oriented approach.

> Note that this repository is automatically mirrored from our own Gitlab instance.
> We will accept issues and merge requests here though!

### Version notes

Version 2 of this bundle only supports Symfony's new authentication manager, introduced in Symfony 5.3. As the security
manager matured in Symfony 5.4, that is the first version this bundle supports. Using the new authentication manager is
required for Symfony 6!

We also require the use of PHP8, as that significantly reduces the maintenance complexity.

Do you need this bundle, but you cannot enable the new authentication manager or use PHP8? Check out
the [v1.x](https://github.com/Drenso/symfony-oidc/tree/v1.x) branch and its documentation!

### Migrate from older versions

Take a look at [UPGRADE.md](https://github.com/Drenso/symfony-oidc/blob/master/UPGRADE.md)!

### Installation

You can add this bundle by simply requiring it with composer:

```php
composer require drenso/symfony-oidc-bundle
```

If you're using Symfony Flex, your `.env` file should have been appended with some environment variables and
a `drenso_oidc.yaml` file should have been created in your configuration directory!

### Setup

##### OIDC Clients

Make sure to configure at least the default OIDC client in the `drenso_oidc.yaml` in your `config/packages` directory.
This can be done using the environment variables already added to your application by Symfony flex, or by updating the
configuration file. You can configure more clients, they will be available under the `drenso.oidc.client.{name}`, and are
autowirable by using `OidcClientInterface ${name}OidcClient`, for example `OidcClientInterface $defaultOidcClient`. If
the name does not match with one of the configured clients, the default client will be autowired.

Configuration example:

```yaml
drenso_oidc:
    #default_client: default # The default client, will be aliased to OidcClientInterface
    clients:
        default: # The client name, each client will be aliased to its name (for example, $defaultOidcClient)
            # Required OIDC client configuration
            well_known_url: '%env(OIDC_WELL_KNOWN_URL)%'
            client_id: '%env(OIDC_CLIENT_ID)%'
            client_secret: '%env(OIDC_CLIENT_SECRET)%'

            # Extra configuration options
            #well_known_parser: ~ # Service id for a custom well-known configuration parser
            #well_known_cache_time: 3600 # Time in seconds, will only be used when symfony/cache is available
            #jwks_cache_time: 3600 # Time in seconds, will only be used when symfony/cache is available
            #token_leeway_seconds: 300 # Leeway time in seconds when validating token validity
            #redirect_route: '/login_check'
            #custom_client_headers: []
            #code_challenge_method: ~ # Code challenge method, can be null, 'S256' or 'plain'
            #disable_nonce: false # Set to true when nonce verification should not be used

        # Add any extra client
        #link: # Will be accessible using $linkOidcClient
            #well_known_url: '%env(LINK_WELL_KNOWN_URL)%'
            #client_id: '%env(LINK_CLIENT_ID)%'
            #client_secret: '%env(LINK_CLIENT_SECRET)%'
```

##### User provider

You will need to update your User Provider to implement the methods from the `OidcUserProviderInterface`. Two methods
need to be implemented:

- `ensureUserExists(string $userIdentifier, OidcUserData $userData)`: Implement this method to bootstrap a new account
  using the data available from the passed `OidcUserData` object. The identifier is a configurable property from the
  user data, which defaults to `sub`. If the account cannot be bootstrapped, authentication will be impossible as the
  User Provider will not be capable of retrieving the user.
- `loadOidcUser(string $userIdentifier): UserInterface`: Implement this method to retrieve the user based on the
  identifier. We use a dedicated method instead of Symfony's default `loadUserByIdentifier` to allow you to detect where
  the login is coming from, without the need of creating a dedicated user provider. If the OIDC user identifiers are
  unique, a forward to the `loadUserByIdentifier` should be sufficient.

##### Firewall configuration

If you are using Symfony <6, make sure to enable the new authentication manager in the `security.yaml`:

```yaml
security:
  enable_authenticator_manager: true
```

Enable the `oidc` listener in the `security.yml` for your firewall:

```yaml
security:
  firewalls:
    main:
      pattern: ^/
      oidc: ~
```

There are a couple of options available for the `oidc` listener.

| Option                           | Default         | Description                                                                                                                                   |
|----------------------------------|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `check_path`                     | `/login_check`  | Only on this path the authenticator will accept authentication. Note that this should match with the redirect configured for the OIDC client. |
| `login_path`                     | `/login`        | The path to forward to when authentication is required                                                                                        | 
| `client`                         | `default`       | The configured OIDC client to use                                                                                                             |
| `user_identifier_property`       | `sub`           | The OidcUserData property to use as unique user identifier                                                                                    |
| `user_identifier_from_idtoken`   | `false`         | The identifier is fetched from the id_token instead of userinfo endpoint                                                                      |
| `enable_remember_me`             | `false`         | Enable "remember me" functionality for authenticator                                                                                          |
| `enable_end_session_listener`    | `false`         | Enable "logout" functionality for authenticator through the "LogoutEvent"                                                                     |
| `use_logout_target_path`         | `true`          | Used for the end session event subscriber                                                                                                     |
| `always_use_default_target_path` | `false`         | Used for the success handler                                                                                                                  |
| `default_target_path`            | `/`             | Used for the success handler                                                                                                                  |
| `target_path_parameter`          | `_target_path`  | Used for the success handler                                                                                                                  |
| `use_referer`                    | `false`         | Used for the success handler                                                                                                                  |
| `failure_path`                   | `null`          | Used for the failure handler                                                                                                                  |
| `failure_forward`                | `false`         | Used for the failure handler                                                                                                                  |
| `failure_path_parameter`         | `_failure_path` | Used for the failure handler                                                                                                                  |

You can configure them directly under the `oidc` listener in your firewall, for example the `user_identifier_property`:

```yaml
security:
  firewalls:
    main:
      oidc:
        user_identifier_property: email
```

##### Start the authentication

Use the controller example below to forward a user to the OIDC service:

```php
  /**
   * This controller forwards the user to the OIDC login
   *
   * @throws \Drenso\OidcBundle\Exception\OidcException
   */
  #[Route('/login_oidc', name: 'login_oidc')]
  #[IsGranted('PUBLIC_ACCESS')]
  public function surfconext(OidcClientInterface $oidcClient): RedirectResponse
  {
    // Redirect to authorization @ OIDC provider
    return $oidcClient->generateAuthorizationRedirect();
  }
```

> It is possible to supply prompt, scopes and additional query parameters to the `generateAuthorizationRedirect` method.

> It is also possible to force remember me mode for the redirect.

That should be all!

### User identifier

By default, this bundle uses the `sub` property as user identifier, but any property from the retrieved user data can be used. Just configure the `user_identifier_property` with an property path string compatible with the [Symfony Property Accessor](https://symfony.com/doc/current/components/property_access.html) to retrieve the value you need.

> Note that the object based access method is used to retrieve the properties from the user data.

### Remember me

If you want to enable remember me functionality make sure that you add the `_remember_me=1` query parameter to the route being used to generate the redirect forward (the one that calls `generateAuthorizationRedirect`).

You can override the `_remember_me` parameter per OIDC client. Just update the `remember_me_parameter` value in the client configuration.

Lastly, make sure the Symfony remember me authenticator is enabled, and that you set the `enable_remember_me` option to true for the `oidc` authenticator in `security.yaml`.

When a user is authenticated, you will see the `REMEMBERME` cookie. You can remove the `PHPSESSID` cookie to check whether remember me is working.

### Logout

It is possible to enable "logout" through the `end_session_support` functionality of the Identity Provider, if the `end_session_endpoint` parameter is present in the .well-known endpoint it can be used.

As logging out is fundamentally broken when using single sign-on, this option is disabled by default. This is due to the fact that logging out at the identity provider (for example: Azure, Facebook, etc) cannot guarantee the user is logged out of any other service that the user has authenticated with using the same identity provider.

If you want to enable the "logout" support, simply add `enable_end_session_listener: true` to your oidc listener in the firewall config. It will only work of you enabled the default Symfony `logout: true` setting in your firewall.

By default, the listener will pass the logout `target_path` to the OpenID Provider, so the user gets redirected back to your application after logging out. If you don't want this and want the user to remain at the logout confirmation page of your OpenID Provider, enable the `use_logout_target_path: false` setting.

**_Example: default logout path_**

```yaml
security:
  firewalls:
    main:
      logout: true
      oidc:
        enable_end_session_listener: true
```

**_Example: custom logout path_**

```yaml
security:
  firewalls:
    main:
      logout:
        target: /my_custom_target_path
      oidc:
        enable_end_session_listener: true
```

**_Example: disable redirect to logout `target_path`_**

This will keep the user at the OpenID provider after login out.
```yaml
security:
  firewalls:
    main:
      logout: true
      oidc:
        enable_end_session_listener: true
        use_logout_target_path: false
```


### Client locator

If for some reason you have several OIDC clients configured and need to retrieve them dynamically, you can use the `OidcClientLocator`.

```php
  public function surfconext(OidcClientLocator $clientLocator): RedirectResponse
  {
    return $clientLocator->getClient('your_client_id')->generateAuthorizationRedirect();
  }
```

The locator will throw an OidcClientNotFoundException when the requested client is not found. When called without an argument, it will return the configured default client.

### Leeway

This bundle uses a 300 seconds leeway when validating the access tokens. This value can be configured with the `token_leeway_seconds` client option.

### Cache

When you have `symfony/cache` available in your project, this library will automatically cache the well known and jwks results. By default, it will be cached for `3600` seconds.

You can disable the caches separately by passing `null` to the `well_known_cache_time` or `jwks_cache_time` client options.

### Refreshing tokens

Currently, the firewall implementation provided by this bundle does not offer refresh tokens (as it should not be necessary).
However, if you need to refresh the tokens yourself for your implementation, you can use the `refreshTokens` method on the `OidcClientInterface`!

### Parsing well-known information

Some providers return incorrect or incomplete well known information. You can configure a custom well-known parser for the `OidcClient` by setting the `well_known_parser` to a service id which implements the `OidcWellKnownParserInterface`.

## Known usages

A list of open source projects that use this bundle:

- Zitadel's [example-symfony-oidc](https://github.com/zitadel/example-symfony-oidc): A template repository with basic OIDC authentication, user model, roles and example pages.
