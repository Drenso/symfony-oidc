<?php

namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Exception\OidcConfigurationException;
use Drenso\OidcBundle\Exception\OidcConfigurationResolveException;
use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\Model\OidcTokens;
use Drenso\OidcBundle\Model\OidcUserData;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * This class implements the Oidc protocol.
 */
interface OidcClientInterface
{
  /**
   * Authenticate the incoming request.
   *
   * @throws OidcException
   */
  public function authenticate(Request $request): OidcTokens;

  /**
   * Use an existing refresh token to retrieve new tokens from the OIDC provider.
   *
   * @throws OidcException
   */
  public function refreshTokens(string $refreshToken): OidcTokens;

  /**
   * Create the redirect that should be followed in order to authorize.
   *
   * @param string|null $prompt One of 'none', 'login', 'consent', 'select_account' or 'create'
   *                            If null or not supplied, the parameter will be omitted from the request
   *                            Note that 'create' is currently in draft and might not be supported by every implementation
   * @param string[]    $scopes An array of scopes to request
   *                            If not supplied it will default to openid
   *
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  public function generateAuthorizationRedirect(?string $prompt = null, array $scopes = ['openid']): RedirectResponse;

  /**
   * Retrieve the user information.
   *
   * @throws OidcException
   */
  public function retrieveUserInfo(OidcTokens $tokens): OidcUserData;
}
