<?php


namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Exception\OidcConfigurationException;
use Drenso\OidcBundle\Exception\OidcConfigurationResolveException;
use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\Model\OidcTokens;
use Drenso\OidcBundle\Security\Exception\OidcAuthenticationException;
use Exception;
use InvalidArgumentException;
use RuntimeException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;

/**
 * This class implements the Oidc protocol.
 */
class OidcClient
{
  const OIDC_SESSION_NONCE = 'oidc.session.nonce';
  const OIDC_SESSION_STATE = 'oidc.session.state';

  /** OIDC configuration values */
  protected ?array $configuration = NULL;

  public function __construct(
      protected SessionInterface $session,
      protected RouterInterface  $router,
      protected OidcUrlFetcher   $urlFetcher,
      protected OidcJwtHelper    $jwtHelper,
      protected string           $wellKnownUrl,
      private string             $clientId,
      private string             $clientSecret,
      private string             $redirectRoute)
  {
    // Check for required phpseclib classes
    if (!class_exists('\phpseclib\Crypt\RSA') && !class_exists('\phpseclib3\Crypt\RSA')) {
      throw new RuntimeException('Unable to find phpseclib Crypt/RSA.php.  Ensure phpseclib/phpseclib is installed.');
    }
  }

  /**
   * Authenticate the incoming request
   *
   * @throws OidcException
   */
  public function authenticate(Request $request): ?OidcTokens
  {
    // Check whether the request has an error state
    if ($request->request->has('error')) {
      throw new OidcAuthenticationException(sprintf("OIDC error: %s. Description: %s.",
          $request->request->get('error', ''), $request->request->get('error_description', '')));
    }

    // Check whether the request contains the required state and code keys
    $code  = $request->query->get('code');
    $state = $request->query->get('state');
    if ($code == NULL || $state == NULL) {
      return NULL;
    }

    // Do a session check
    if ($state != $request->getSession()->get(self::OIDC_SESSION_STATE)) {
      // Fail silently
      return NULL;
    }

    // Clear session after check
    $request->getSession()->remove(self::OIDC_SESSION_STATE);

    // Request the tokens
    $tokens = $this->requestTokens($code);

    // Retrieve the claims
    $claims = $this->jwtHelper->decodeJwt($tokens->getIdToken(), 1);

    // Verify the token
    if (!$this->jwtHelper->verifyJwtSignature($this->getJwktUri(), $tokens)) {
      throw new OidcAuthenticationException ("Unable to verify signature");
    }

    // If this is a valid claim
    if ($this->jwtHelper->verifyJwtClaims($this->getIssuer(), $claims, $tokens)) {
      return $tokens;
    } else {
      throw new OidcAuthenticationException("Unable to verify JWT claims");
    }

  }

  /**
   * Create the redirect that should be followed in order to authorize
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
  public function generateAuthorizationRedirect(?string $prompt = NULL, array $scopes = ['openid']): RedirectResponse
  {
    $data = [
        'client_id'     => $this->clientId,
        'response_type' => 'code',
        'redirect_uri'  => $this->getRedirectUrl(),
        'scope'         => implode(' ', $scopes),
        'state'         => $this->generateState(),
        'nonce'         => $this->generateNonce(),
    ];

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

    return new RedirectResponse(sprintf('%s?%s', $this->getAuthorizationEndpoint(), http_build_query($data)));
  }

  /**
   * Retrieve the user information
   *
   * @throws OidcException
   */
  public function retrieveUserInfo(OidcTokens $tokens): mixed
  {
    // Set the authorization header
    $headers = ["Authorization: Bearer {$tokens->getAccessToken()}"];

    // Retrieve the user information and convert the encoding to UTF-8 to harden for surfconext UTF-8 bug
    $jsonData = $this->urlFetcher->fetchUrl($this->getUserinfoEndpoint(), NULL, $headers);
    $jsonData = mb_convert_encoding($jsonData, 'UTF-8');

    // Read the data
    $data = json_decode($jsonData, true);

    // Check data due
    if ($data === NULL) {
      throw new OidcException("Error retrieving the user info from the endpoint.");
    }

    return $data;
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getAuthorizationEndpoint(): mixed
  {
    return $this->getConfigurationValue('authorization_endpoint');
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getIssuer()
  {
    return $this->getConfigurationValue('issuer');
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getJwktUri(): mixed
  {
    return $this->getConfigurationValue('jwks_uri');
  }

  protected function getRedirectUrl(): string
  {
    return $this->router->generate($this->redirectRoute, [], UrlGeneratorInterface::ABSOLUTE_URL);
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getTokenEndpoint(): mixed
  {
    return $this->getConfigurationValue('token_endpoint');
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getTokenEndpointAuthMethods(): mixed
  {
    return $this->getConfigurationValue('token_endpoint_auth_methods_supported');
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  protected function getUserinfoEndpoint(): mixed
  {
    return $this->getConfigurationValue('userinfo_endpoint');
  }

  /**
   * Generate a nonce to verify the response
   */
  private function generateNonce(): string
  {
    $value = $this->generateRandomString();

    $this->session->set(self::OIDC_SESSION_NONCE, $value);

    return $value;
  }

  /**
   * Generate a secure random string for usage as state
   */
  private function generateRandomString(): string
  {
    return md5(openssl_random_pseudo_bytes(25));
  }

  /**
   * Generate a state to identify the request
   */
  private function generateState(): string
  {
    $value = $this->generateRandomString();
    $this->session->set(self::OIDC_SESSION_STATE, $value);

    return $value;
  }

  /**
   * Retrieve a configuration value from the provider well-known configuration
   *
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   */
  private function getConfigurationValue(string $key): mixed
  {
    // Resolve the configuration
    $this->resolveConfiguration();

    if (!array_key_exists($key, $this->configuration)) {
      throw new OidcConfigurationException($key);
    }

    return $this->configuration[$key];
  }

  /**
   * Request the tokens from the OIDC provider
   *
   * @throws OidcException
   */
  private function requestTokens(string $code): OidcTokens
  {
    $params = [
        'grant_type'    => 'authorization_code',
        'code'          => $code,
        'redirect_uri'  => $this->getRedirectUrl(),
        'client_id'     => $this->clientId,
        'client_secret' => $this->clientSecret,
    ];

    // Use basic auth if offered
    $headers = [];
    if (in_array('client_secret_basic', $this->getTokenEndpointAuthMethods())) {
      $headers = ['Authorization: Basic ' . base64_encode(urlencode($this->clientId) . ':' . urlencode($this->clientSecret))];
      unset($params['client_secret']);
    }

    $jsonToken = json_decode($this->urlFetcher->fetchUrl($this->getTokenEndpoint(), $params, $headers));

    // Throw an error if the server returns one
    if (isset($jsonToken->error)) {
      if (isset($jsonToken->error_description)) {
        throw new OidcAuthenticationException($jsonToken->error_description);
      }
      throw new OidcAuthenticationException(sprintf('Got response: %s', $jsonToken->error));
    }

    return new OidcTokens($jsonToken);
  }

  /**
   * Retrieves the well-known configuration and saves it in the class
   *
   * @throws OidcConfigurationResolveException
   */
  private function resolveConfiguration(): void
  {
    // Check whether the configuration is already available
    if ($this->configuration !== NULL) return;

    try {
      $wellKnown = $this->urlFetcher->fetchUrl($this->wellKnownUrl);
    } catch (Exception $e) {
      throw new OidcConfigurationResolveException(sprintf('Could not retrieve OIDC configuration from "%s".', $this->wellKnownUrl), 0, $e);
    }

    // Parse the configuration
    if (($config = json_decode($wellKnown, true)) === NULL) {
      throw new OidcConfigurationResolveException(sprintf('Could not parse OIDC configuration. Response data: "%s"', $wellKnown));
    }

    // Set the configuration
    $this->configuration = $config;
  }
}
