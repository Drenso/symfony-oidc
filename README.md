# Symfony OIDC bundle

This bundle can be used to add OIDC support to any application. Currently it has only been tested with SURFconext OIDC.

### Composer

You can add this bundle to the `composer.json`. You will need to create a new api-key for every project 
(with the deploy user). See the example below:

```php
{
    "repositories": [
        {
            "type": "gitlab",
            "url":  "git@gitlab.drenso.nl:intern/symfony-oidc.git"
        }
    ],
    "require": {
        "drenso/symfony-oidc-bundle": "v1.0.1",
    },
    "config": {
        "gitlab-domains": [
            "gitlab.drenso.nl"
        ],
        "gitlab-token": {"gitlab.drenso.nl": "<api-token>"}
    },
}
```

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

Also, register the security listeners:

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

Add the ListenerFactory to the `Kernel.php`:

```php
  /**
   * @param ContainerBuilder $container
   */
  protected function build(ContainerBuilder $container)
  {

    // Register the Oidc factory
    $extension = $container->getExtension('security');
    assert($extension instanceof SecurityExtension);
    $extension->addSecurityListenerFactory(new OidcFactory());
  }
```

Lastly, make sure that the your custom UserProvider implements the `OidcUserProviderInterface`.
