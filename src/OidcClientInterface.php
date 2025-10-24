<?php

namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Enum\OidcTokenType;
use Drenso\OidcBundle\Exception\OidcCodeChallengeMethodNotSupportedException;
use Drenso\OidcBundle\Exception\OidcConfigurationException;
use Drenso\OidcBundle\Exception\OidcConfigurationResolveException;
use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\Model\AccessTokens;
use Drenso\OidcBundle\Model\OidcIntrospectionData;
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
  public function refreshTokens(string $refreshToken, ?string $targetScope = null): OidcTokens;

  /**
   * Use an existing auth token to retrieve new tokens from the OIDC provider with another scope and/or audience.
   *
   * @throws OidcException
   */
  public function exchangeTokens(string $accessToken, ?string $targetScope = null, ?string $targetAudience = null): AccessTokens;

  /**
   * Create the redirect that should be followed in order to authorize.
   *
   * @param string|null           $prompt                One of 'none', 'login', 'consent', 'select_account' or 'create'
   *                                                     If null or not supplied, the parameter will be omitted from the request
   *                                                     Note that 'create' is currently in draft and might not be supported by every implementation
   * @param string[]              $scopes                An array of scopes to request
   *                                                     If not supplied it will default to openid
   * @param bool                  $forceRememberMe       when set, the "remember me" security trigger will be force regardless of the
   *                                                     presence of the "remember me" parameter in the current request
   * @param array<string, string> $additionalQueryParams additional query parameters which will be added to the generated redirect request
   *
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   * @throws OidcCodeChallengeMethodNotSupportedException When the IdP doesn't support the request code challenge method
   */
  public function generateAuthorizationRedirect(
    ?string $prompt = null,
    array $scopes = ['openid'],
    bool $forceRememberMe = false,
    array $additionalQueryParams = [],
  ): RedirectResponse;

  /**
   * Create the redirect that should be followed in order to end the current session.
   *
   * @param OidcTokens            $tokens                OidcTokens object containing the information to pass to the end_session endpoint
   * @param string|null           $postLogoutRedirectUrl Contains the url where the provider redirects the user to after logging out
   * @param array<string, string> $additionalQueryParams additional query parameters which will be added to the generated redirect request
   *
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  public function generateEndSessionEndpointRedirect(
    OidcTokens $tokens,
    ?string $postLogoutRedirectUrl,
    array $additionalQueryParams = [],
  ): RedirectResponse;

  /**
   * Retrieve the user information.
   *
   * @throws OidcException
   */
  public function retrieveUserInfo(OidcTokens $tokens): OidcUserData;

  /**
   * Introspect the supplied token.
   *
   * @throws OidcException
   */
  public function introspect(OidcTokens $tokens, ?OidcTokenType $tokenType = null): OidcIntrospectionData;
}
