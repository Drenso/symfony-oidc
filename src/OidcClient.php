<?php

namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Exception\OidcCodeChallengeMethodNotSupportedException;
use Drenso\OidcBundle\Exception\OidcConfigurationException;
use Drenso\OidcBundle\Exception\OidcConfigurationResolveException;
use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\Model\OidcTokens;
use Drenso\OidcBundle\Model\OidcUserData;
use Drenso\OidcBundle\Security\Exception\OidcAuthenticationException;
use Exception;
use InvalidArgumentException;
use LogicException;
use RuntimeException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\String\Slugger\AsciiSlugger;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * This class implements the Oidc protocol.
 */
class OidcClient implements OidcClientInterface
{
  /** OIDC configuration values */
  protected ?array $configuration = null;
  private ?string $cacheKey       = null;
  private const PKCE_ALGORITHMS   = [
    'S256'  => 'sha256',
    'plain' => false,
  ];

  public function __construct(
    protected RequestStack $requestStack,
    protected HttpUtils $httpUtils,
    protected ?CacheInterface $wellKnownCache,
    protected OidcUrlFetcher $urlFetcher,
    protected OidcSessionStorage $sessionStorage,
    protected OidcJwtHelper $jwtHelper,
    protected string $wellKnownUrl,
    private readonly ?int $wellKnownCacheTime,
    private readonly string $clientId,
    private readonly string $clientSecret,
    private readonly string $redirectRoute,
    private readonly string $rememberMeParameter,
    protected ?OidcWellKnownParserInterface $wellKnownParser = null,
    private readonly ?string $codeChallengeMethod = null,
    private readonly bool $disableNonce = false)
  {
    if (!$this->wellKnownUrl || filter_var($this->wellKnownUrl, FILTER_VALIDATE_URL) === false) {
      throw new LogicException(sprintf('Invalid well known url (%s) for OIDC', $this->wellKnownUrl));
    }

    if ($this->codeChallengeMethod && !array_key_exists($this->codeChallengeMethod, self::PKCE_ALGORITHMS)) {
      throw new LogicException(sprintf('Invalid PKCE algorithm (%s) for code challenge method', $this->codeChallengeMethod));
    }
  }

  public function authenticate(Request $request): OidcTokens
  {
    // Check whether the request has an error state
    if ($request->request->has('error')) {
      throw new OidcAuthenticationException(sprintf('OIDC error: %s. Description: %s.',
        $request->request->get('error', ''), $request->request->get('error_description', '')));
    }

    // Check whether the request contains the required state and code keys
    if (!$code = $request->query->get('code')) {
      throw new OidcAuthenticationException('Missing code in query');
    }
    if (!$state = $request->query->get('state')) {
      throw new OidcAuthenticationException('Missing state in query');
    }

    // Do a session check
    if ($state != $this->sessionStorage->getState()) {
      // Fail silently
      throw new OidcAuthenticationException('Invalid session state');
    }

    // Clear session after check
    $this->sessionStorage->clearState();

    // Request and verify the tokens
    return $this->verifyTokens(
      $this->requestTokens('authorization_code', $code, $this->getRedirectUrl()),
      !$this->disableNonce
    );
  }

  public function refreshTokens(string $refreshToken): OidcTokens
  {
    // Clear session after check
    $this->sessionStorage->clearState();

    // Request and verify the tokens
    return $this->verifyTokens(
      $this->requestTokens('refresh_token', null, null, $refreshToken),
      verifyNonce: false
    );
  }

  public function generateAuthorizationRedirect(
    ?string $prompt = null,
    array $scopes = ['openid'],
    bool $forceRememberMe = false,
    array $additionalQueryParams = []): RedirectResponse
  {
    $data = array_merge($additionalQueryParams, [
      'client_id'     => $this->clientId,
      'response_type' => 'code',
      'redirect_uri'  => $this->getRedirectUrl(),
      'scope'         => implode(' ', $scopes),
      'state'         => $this->generateState(),
    ]);

    if (!$this->disableNonce) {
      $data['nonce'] = $this->generateNonce();
    }

    if ($prompt) {
      $validPrompts = ['none', 'login', 'consent', 'select_account', 'create'];
      if (!in_array($prompt, $validPrompts)) {
        throw new InvalidArgumentException(sprintf(
          'The prompt parameter need to be one of ("%s"), but "%s" given',
          implode('", "', $validPrompts),
          $prompt
        ));
      }

      $data['prompt'] = $prompt;
    }

    if ($this->codeChallengeMethod) {
      $data = array_merge($data, [
        'code_challenge'        => $this->generateCodeChallenge(),
        'code_challenge_method' => $this->codeChallengeMethod,
      ]);
    }

    // Store remember me state
    /** @phan-suppress-next-line PhanAccessMethodInternal */
    $parameter = $this->requestStack->getCurrentRequest()->get($this->rememberMeParameter);
    $this->sessionStorage->storeRememberMe($forceRememberMe || 'true' === $parameter || 'on' === $parameter || '1' === $parameter || 'yes' === $parameter || true === $parameter);

    // Remove security session state
    $session = $this->requestStack->getSession();

    // BC for attribute definition
    $session->remove(match (true) {
      // Symfony 7
      defined('\Symfony\Component\Security\Http\SecurityRequestAttributes::AUTHENTICATION_ERROR') => \Symfony\Component\Security\Http\SecurityRequestAttributes::AUTHENTICATION_ERROR,
      // Symfony 6
      /* @phan-suppress-next-line PhanUndeclaredConstantOfClass */
      defined('\Symfony\Bundle\SecurityBundle\Security::AUTHENTICATION_ERROR') => \Symfony\Bundle\SecurityBundle\Security::AUTHENTICATION_ERROR,
      // Symfony 5
      /* @phan-suppress-next-line PhanUndeclaredClassConstant */
      default => \Symfony\Component\Security\Core\Security::AUTHENTICATION_ERROR,
    });
    $session->remove(match (true) {
      // Symfony 7
      defined('\Symfony\Component\Security\Http\SecurityRequestAttributes::LAST_USERNAME') => \Symfony\Component\Security\Http\SecurityRequestAttributes::LAST_USERNAME,
      // Symfony 6
      /* @phan-suppress-next-line PhanUndeclaredConstantOfClass */
      defined('\Symfony\Bundle\SecurityBundle\Security::LAST_USERNAME') => \Symfony\Bundle\SecurityBundle\Security::LAST_USERNAME,
      // Symfony 5
      /* @phan-suppress-next-line PhanUndeclaredClassConstant */
      default => \Symfony\Component\Security\Core\Security::LAST_USERNAME,
    });

    $endpointHasQuery = parse_url($this->getAuthorizationEndpoint(), PHP_URL_QUERY);

    return new RedirectResponse(sprintf('%s%s%s', $this->getAuthorizationEndpoint(), $endpointHasQuery ? '&' : '?', http_build_query($data)));
  }

  public function generateEndSessionEndpointRedirect(
    OidcTokens $tokens,
    ?string $postLogoutRedirectUrl = null,
    array $additionalQueryParams = []): RedirectResponse
  {
    $data = array_merge($additionalQueryParams, [
      'client_id'     => $this->clientId,
      'id_token_hint' => $tokens->getIdToken(),
    ]);

    if (null !== $postLogoutRedirectUrl) {
      $data = array_merge($data, [
        'post_logout_redirect_uri' => $postLogoutRedirectUrl,
      ]);
    }

    $endpointHasQuery = parse_url($this->getEndSessionEndpoint(), PHP_URL_QUERY);

    return new RedirectResponse(sprintf('%s%s%s', $this->getEndSessionEndpoint(), $endpointHasQuery ? '&' : '?', http_build_query($data)));
  }

  public function retrieveUserInfo(OidcTokens $tokens): OidcUserData
  {
    // Set the authorization header
    $headers = ["Authorization: Bearer {$tokens->getAccessToken()}"];

    // Retrieve the user information and convert the encoding to UTF-8 to harden for surfconext UTF-8 bug
    $jsonData = $this->urlFetcher->fetchUrl($this->getUserinfoEndpoint(), null, $headers);
    $jsonData = mb_convert_encoding($jsonData, 'UTF-8');

    // Read the data
    $data = json_decode($jsonData, true);

    // Check data due
    if (!is_array($data)) {
      throw new OidcException('Error retrieving the user info from the endpoint.');
    }

    return new OidcUserData($data);
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getAuthorizationEndpoint(): string
  {
    return $this->getConfigurationValue('authorization_endpoint');
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getEndSessionEndpoint(): string
  {
    return $this->getConfigurationValue('end_session_endpoint');
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getIssuer(): string
  {
    return $this->getConfigurationValue('issuer');
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getJwksUri(): string
  {
    return $this->getConfigurationValue('jwks_uri');
  }

  protected function getRedirectUrl(): string
  {
    return $this->httpUtils->generateUri($this->requestStack->getCurrentRequest(), $this->redirectRoute);
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getTokenEndpoint(): string
  {
    return $this->getConfigurationValue('token_endpoint');
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getTokenEndpointAuthMethods(): array
  {
    return $this->getConfigurationValue('token_endpoint_auth_methods_supported', ['client_secret_basic']);
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getCodeChallengeMethodsSupported(): array
  {
    $value = $this->getConfigurationValue('code_challenge_methods_supported');

    if (!is_array($value)) {
      return [];
    }

    return $value;
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getUserinfoEndpoint(): string
  {
    return $this->getConfigurationValue('userinfo_endpoint');
  }

  /** Generate a nonce to verify the response */
  private function generateNonce(): string
  {
    $value = $this->generateRandomString();

    $this->sessionStorage->storeNonce($value);

    return $value;
  }

  /**
   * Generate a code challenge based on the code verifier and PKCE Algorithm.
   *
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   * @throws OidcCodeChallengeMethodNotSupportedException
   */
  private function generateCodeChallenge(): string
  {
    if (null === $this->codeChallengeMethod) {
      throw new RuntimeException('Method should not called when a code challenge method isn\'t conmfigured');
    }

    if (!in_array($this->codeChallengeMethod, $this->getCodeChallengeMethodsSupported(), true)) {
      throw new OidcCodeChallengeMethodNotSupportedException($this->codeChallengeMethod);
    }

    $codeVerifier = bin2hex(random_bytes(64));

    // Save the code verifier for later use in token verification
    $this->sessionStorage->storeCodeVerifier($codeVerifier);

    $pkceAlgorithm = self::PKCE_ALGORITHMS[$this->codeChallengeMethod];

    // if $pkceAlgorithm is false handle it as plain
    if (!$pkceAlgorithm) {
      $codeChallenge = $codeVerifier;
    } else {
      $codeChallenge = rtrim(strtr(base64_encode(hash(self::PKCE_ALGORITHMS[$this->codeChallengeMethod], $codeVerifier, true)), '+/', '-_'), '=');
    }

    return $codeChallenge;
  }

  /** Generate a secure random string for usage as state */
  private function generateRandomString(): string
  {
    return md5(random_bytes(25));
  }

  /** Generate a state to identify the request */
  private function generateState(): string
  {
    $value = $this->generateRandomString();
    $this->sessionStorage->storeState($value);

    return $value;
  }

  /**
   * Retrieve a configuration value from the provider well-known configuration.
   *
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  private function getConfigurationValue(string $key, mixed $default = null): mixed
  {
    // Resolve the configuration
    $this->resolveConfiguration();

    if (!array_key_exists($key, $this->configuration)) {
      return $default ?? throw new OidcConfigurationException($key);
    }

    return $this->configuration[$key];
  }

  /**
   * Request the tokens from the OIDC provider.
   *
   * @throws OidcException
   */
  private function requestTokens(
    string $grantType,
    ?string $code = null,
    ?string $redirectUrl = null,
    ?string $refreshToken = null): OidcTokens
  {
    $params = [
      'grant_type'    => $grantType,
      'client_id'     => $this->clientId,
      'client_secret' => $this->clientSecret,
    ];

    if (null !== $code) {
      $params['code'] = $code;
    }

    if (null !== $redirectUrl) {
      $params['redirect_uri'] = $redirectUrl;
    }

    if (null !== $refreshToken) {
      $params['refresh_token'] = $refreshToken;
    }

    // Use basic auth if offered
    $headers = [];
    if (in_array('client_secret_basic', $this->getTokenEndpointAuthMethods())) {
      $headers = ['Authorization: Basic ' . base64_encode(urlencode($this->clientId) . ':' . urlencode($this->clientSecret))];
      unset($params['client_id']);
      unset($params['client_secret']);
    }

    if ($codeVerifier = $this->sessionStorage->getCodeVerifier()) {
      unset($params['client_secret']);

      $params = array_merge($params, [
        'code_verifier' => $codeVerifier,
      ]);
    }

    $jsonToken = json_decode($this->urlFetcher->fetchUrl($this->getTokenEndpoint(), $params, $headers));

    // Throw an error if the server returns one
    if (isset($jsonToken->error)) {
      if (isset($jsonToken->error_description)) {
        throw new OidcAuthenticationException($jsonToken->error_description);
      }
      throw new OidcAuthenticationException(sprintf('Got response: %s', $jsonToken->error));
    }

    // Clear code verifier from session after check
    $this->sessionStorage->clearCodeVerifier();

    return new OidcTokens($jsonToken);
  }

  /** @throws OidcException */
  private function verifyTokens(OidcTokens $tokens, $verifyNonce = true): OidcTokens
  {
    $this->jwtHelper->verifyTokens($this->getIssuer(), $this->getJwksUri(), $tokens, $verifyNonce);

    return $tokens;
  }

  /**
   * Retrieves the well-known configuration and saves it in the class.
   *
   * @phan-suppress PhanTypeInvalidThrowsIsInterface
   *
   * @throws OidcConfigurationResolveException
   */
  private function resolveConfiguration(): void
  {
    // Check whether the configuration is already available
    if ($this->configuration !== null) {
      return;
    }

    if ($this->wellKnownCache && $this->wellKnownCacheTime !== null) {
      try {
        $this->cacheKey ??= '_drenso_oidc_client__well_known__' . (new AsciiSlugger('en'))->slug($this->wellKnownUrl);
        $config         = $this->wellKnownCache->get($this->cacheKey, function (ItemInterface $item) {
          $item->expiresAfter($this->wellKnownCacheTime);

          return $this->retrieveWellKnownConfiguration();
        });
      } catch (\Psr\Cache\InvalidArgumentException $e) {
        throw new OidcConfigurationResolveException('Cache failed: ' . $e->getMessage(), previous: $e);
      }
    } else {
      $config = $this->retrieveWellKnownConfiguration();
    }

    // Set the configuration
    $this->configuration = $config;
  }

  /**
   * Retrieves the well-known configuration from the configured url.
   *
   * @throws OidcConfigurationResolveException
   */
  private function retrieveWellKnownConfiguration(): array
  {
    try {
      $wellKnown = $this->urlFetcher->fetchUrl($this->wellKnownUrl);
    } catch (Exception $e) {
      throw new OidcConfigurationResolveException(sprintf('Could not retrieve OIDC configuration from "%s".', $this->wellKnownUrl), 0, $e);
    }

    // Parse the configuration
    if (($config = json_decode($wellKnown, true)) === null) {
      throw new OidcConfigurationResolveException(sprintf('Could not parse OIDC configuration. Response data: "%s"', $wellKnown));
    }

    return $this->wellKnownParser?->parseWellKnown($config) ?? $config;
  }
}
