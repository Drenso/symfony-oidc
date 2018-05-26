# Symfony OIDC bundle

This bundle can be used to add OIDC support to any application. Currently it has only been tested with SURFconext OIDC.

### Composer

You can add this bundle to the `composer.json` by defining the security options: see [Composer docs](https://getcomposer.org/doc/articles/handling-private-packages-with-satis.md#security). 

You will need to create a new deploy key for every installation (dev or prod).

### Usage

You will need to register the `OidcClient` in your `services.yaml` to pass the required text parameters:

```yaml
parameters:
  oidc.well_known_url: '%env(OIDC_WELL_KNOWN)%'
  oidc.client_id: '%env(OIDC_CLIENT_ID)%'
  oidc.client_secret: '%env(file:OIDC_SECRET_FILE)%'

services:
  Drenso\OidcBundle\OidcClient:
    arguments:
      $wellKnownUrl: '%oidc.well_known_url%'
      $clientId: '%oidc.client_id%'
      $clientSecret: '%oidc.client_secret%'
```

Use the controller below to forward an user to the OIDC service:

```php
  /**
   * This controller forward the user to the SURFconext login
   *
   * @Route("/login_surf", name="login_surf")
   * @IsGranted("IS_AUTHENTICATED_ANONYMOUSLY")
   *
   * @param SessionInterface $session
   * @param OidcClient       $oidc
   *
   * @return RedirectResponse
   *
   * @throws \App\Oidc\Exception\OidcConfigurationException
   * @throws \App\Oidc\Exception\OidcConfigurationResolveException
   */
  public function surfconext(SessionInterface $session, OidcClient $oidc)
  {
    // Remove errors from state
    $session->remove(Security::AUTHENTICATION_ERROR);
    $session->remove(Security::LAST_USERNAME);

    // Redirect to authorization @ surfconext
    return $oidc->generateAuthorizationRedirect();
  }
```

Enable the `oidc` listener in the `security.yml`:
```yaml
security:
  firewalls:
    main:
      pattern: ^/
      oidc: ~
```

Lastly, make sure that the your custom UserProvider implements the `OidcUserProviderInterface`.
