# Symfony OIDC bundle

This bundle can be used to add OIDC support to any application. Currently it has only been tested with SURFconext OIDC.

Many thanks to https://github.com/jumbojett/OpenID-Connect-PHP for the implementation which this bundle uses 
although adjusted to be more object oriented.

> Note that this repository is automatically mirrored from our own Gitlab instance. 
> We will accept issues and merge requests here though!

### Composer

You can add this bundle by simply requiring it with composer:

```php
composer require drenso/symfony-oidc-bundle
```

### Usage

You will need to register the `OidcClient` in your `services.yaml` to pass the required text parameters:

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
   * @throws \Drenso\OidcBundle\Exception\OidcConfigurationException
   * @throws \Drenso\OidcBundle\Exception\OidcConfigurationResolveException
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

> It is possible to supply the prompt parameter to the `generateAuthorizationRedirect` method.

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


# FAQ

- **I'm missing the `login_check` route?**

  See https://github.com/Drenso/symfony-oidc/issues/5 for a solution.
