<?php

namespace Drenso\OidcBundle;

use DateInterval;
use DateTimeImmutable;
use Drenso\OidcBundle\Enum\OidcTokenType;
use Drenso\OidcBundle\Exception\OidcConfigurationException;
use Drenso\OidcBundle\Exception\OidcConfigurationResolveException;
use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\Model\OidcTokens;
use Drenso\OidcBundle\Model\UnvalidatedOidcTokens;
use Drenso\OidcBundle\Security\Exception\InvalidJwtTokenException;
use Drenso\OidcBundle\Security\Exception\OidcAuthenticationException;
use Exception;
use JsonException;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Rsa\Sha384;
use Lcobucci\JWT\Signer\Rsa\Sha512;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use phpseclib3\Crypt\PublicKeyLoader;
use Psr\Cache\InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Symfony\Component\String\Slugger\AsciiSlugger;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Contains helper functions to decode/verify JWT data.
 *
 * @phpstan-type JwkObject object{kty: string, kid: string, alg: string}
 */
class OidcJwtHelper
{
  private static ?ParserInterface $parser = null;
  private static ?Validator $validator    = null;

  /** @var list<JwkObject> */
  protected ?array $jwks     = null;
  protected ?string $jwksUri = null;
  private ?string $cacheKey  = null;

  /** @param non-empty-string $clientId */
  public function __construct(
    protected readonly ?CacheInterface $jwksCache,
    protected ?ClockInterface $clock,
    protected readonly OidcUrlFetcher $urlFetcher,
    protected readonly ?OidcSessionStorage $sessionStorage,
    protected readonly string $clientId,
    protected readonly ?int $jwksCacheTime = 3600,
    protected readonly int $leewaySeconds = 300,
    protected readonly ?OidcTokenConstraintProviderInterface $oidcTokenConstraintProvider = null)
  {
  }

  /** @throws InvalidJwtTokenException When the token is not a valid JWT */
  public static function parseToken(string $token): UnencryptedToken
  {
    try {
      if (!$token) {
        throw new InvalidJwtTokenException('Token string cannot be empty');
      }

      $parsedToken = (self::$parser ??= new Parser(new JoseEncoder()))->parse($token);
    } catch (InvalidTokenStructure $e) {
      throw new InvalidJwtTokenException('Invalid token structure', previous: $e);
    }

    /** @noinspection PhpConditionAlreadyCheckedInspection */
    if (!$parsedToken instanceof UnencryptedToken) {
      throw new InvalidJwtTokenException('Not an unencrypted token.');
    }

    return $parsedToken;
  }

  /**
   * Validate the supplied OidcTokens.
   *
   * @param non-empty-string $issuer
   *
   * @throws OidcConfigurationResolveException|OidcConfigurationException Thrown on invalid configuration
   * @throws OidcAuthenticationException                                  Throw when a token is invalid
   */
  public function verifyTokens(string $issuer, string $jwksUri, OidcTokens $tokens, bool $verifyNonce): void
  {
    $this->verifyIdToken($issuer, $jwksUri, $tokens, $verifyNonce);
    $this->verifyAccessToken($issuer, $jwksUri, $tokens, $verifyNonce);
  }

  /**
   * @param non-empty-string $issuer
   *
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   * @throws OidcAuthenticationException
   */
  public function verifyIdToken(string $issuer, string $jwksUri, OidcTokens $tokens, bool $verifyNonce): void
  {
    $idToken     = $tokens->getTokenByType(OidcTokenType::ID) ?? throw new OidcException('ID token missing');
    $accessToken = $tokens->getTokenByType(OidcTokenType::ACCESS);

    $additionalIdTokenConstraints = $this->oidcTokenConstraintProvider?->getAdditionalConstraints(OidcTokenType::ID) ?? [];
    try {
      $this->verifyToken($issuer, $jwksUri, OidcTokenType::ID, self::parseToken($idToken), $verifyNonce, $accessToken, ...$additionalIdTokenConstraints);
    } catch (InvalidJwtTokenException $e) {
      throw new OidcAuthenticationException('Invalid ID token', $e);
    }
  }

  /**
   * @param non-empty-string $issuer
   *
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   * @throws OidcAuthenticationException
   */
  public function verifyAccessToken(string $issuer, string $jwksUri, UnvalidatedOidcTokens $tokens, bool $verifyNonce): void
  {
    $accessToken                      = $tokens->getTokenByType(OidcTokenType::ACCESS) ?? throw new OidcException('Access token missing');
    $additionalAccessTokenConstraints = $this->oidcTokenConstraintProvider?->getAdditionalConstraints(OidcTokenType::ACCESS) ?? [];
    try {
      $this->verifyToken($issuer, $jwksUri, OidcTokenType::ACCESS, self::parseToken($accessToken), false, null, ...$additionalAccessTokenConstraints);
    } catch (InvalidJwtTokenException) {
      // An access token is not required to be a JWT token.
      // If it cannot be parsed as token, ignore it and skip validation
    }
  }

  /**
   * Validate a token.
   *
   * @param non-empty-string $issuer
   *
   * @throws OidcConfigurationResolveException|OidcConfigurationException Thrown on invalid configuration
   * @throws OidcAuthenticationException                                  Throw when a token is invalid
   */
  public function verifyToken(
    string $issuer,
    string $jwksUri,
    OidcTokenType $tokenType,
    UnencryptedToken $token,
    bool $verifyNonce,
    ?string $accessToken = null,
    Constraint ...$additionalConstraints): void
  {
    self::$validator ??= new Validator();

    // Parse the token
    $signer = $this->getTokenSigner($token);
    $key    = $this->getTokenKey($jwksUri, $token);

    try {
      self::$validator->assert($token, new SignedWith($signer, $key));
    } catch (RequiredConstraintsViolated $e) {
      throw new OidcAuthenticationException(
        "Unable to verify signature - {$e->getMessage()}",
        previous: $e
      );
    }

    // Default claims
    $constraints          = [];
    $issuedByConstraint   = new IssuedBy($issuer);
    $looseValidConstraint = new LooseValidAt($this->getClock(), new DateInterval("PT{$this->leewaySeconds}S"));

    switch ($tokenType) {
      case OidcTokenType::ID:
        $constraints = [
          $issuedByConstraint,
          $looseValidConstraint,
          new PermittedFor($this->clientId),
        ];

        if ($token->claims()->has('at_hash') && $accessToken) {
          // Validate the at (access token) hash
          $bit = substr((string)$token->headers()->get('alg'), 2, 3);
          if (!$bit || !is_numeric($bit)) {
            throw new OidcAuthenticationException('Could not determine at hash algorithm');
          }

          $constraints[] = new HasClaimWithValue(
            'at_hash',
            self::urlEncode(
              substr(hash("sha$bit", $accessToken, true), 0, (int)($bit / 16)),
            ),
          );
        }

        if ($verifyNonce) {
          if (!$this->sessionStorage) {
            throw new OidcConfigurationException('Session storage has not been configured for nonce validation');
          }

          $constraints[] = new HasClaimWithValue('nonce', $this->sessionStorage->getNonce());
          $this->sessionStorage->clearNonce();
        }

        break;
      case OidcTokenType::ACCESS:
      case OidcTokenType::REFRESH:
        if ($token->claims()->has(RegisteredClaims::ISSUER)) {
          $constraints[] = $issuedByConstraint;
        }

        if ($token->claims()->has(RegisteredClaims::ISSUED_AT)
          && $token->claims()->has(RegisteredClaims::NOT_BEFORE)
          && $token->claims()->has(RegisteredClaims::EXPIRATION_TIME)) {
          $constraints[] = $looseValidConstraint;
        }

        if (empty($constraints) && empty($additionalConstraints)) {
          // No constraints defined
          return;
        }

        break;
    }

    try {
      self::$validator->assert($token, ...$constraints, ...$additionalConstraints);
    } catch (RequiredConstraintsViolated $e) {
      throw new OidcAuthenticationException(
        "Unable to verify JWT claims - {$e->getMessage()}",
        previous: $e
      );
    }
  }

  /** @throws OidcConfigurationResolveException */
  private function getTokenKey(string $jwksUri, Token $token): Key
  {
    try {
      $jwks                = $this->getJwks($jwksUri);
      $matchingJwkForToken = $this->getMatchingJwkForToken($jwks, $token);
    } catch (OidcAuthenticationException $e) {
      if (!$this->isCacheEnabled()) {
        throw $e;
      }

      // Try again, but force without cache in case a new key was added
      $jwks                = $this->getJwks($jwksUri, true);
      $matchingJwkForToken = $this->getMatchingJwkForToken($jwks, $token);
    }

    try {
      // phpseclib is used to load the JWK, but it requires a single JWK to be JSON encoded
      $jwkData = json_encode(['keys' => [$matchingJwkForToken]], JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
      throw new OidcAuthenticationException('Failed to generate JWK json data', previous: $e);
    }

    try {
      return InMemory::plainText(PublicKeyLoader::loadPublicKey($jwkData)->toString('pkcs8'));
    } catch (Exception $e) {
      throw new OidcAuthenticationException('Failed to load JWK', previous: $e);
    }
  }

  private function getTokenSigner(Token $token): Signer
  {
    $algorithm = $token->headers()->get('alg');
    if (!is_string($algorithm)) {
      throw new OidcAuthenticationException('Invalid JWT token header, missing signature algorithm');
    }

    $keyAlgorithm = match ($algorithm) {
      'RS256' => new Sha256(),
      'RS384' => new Sha384(),
      'RS512' => new Sha512(),
      'ES256' => new Ecdsa\Sha256(),
      'ES384' => new Ecdsa\Sha384(),
      'ES512' => new Ecdsa\Sha512(),
      default => throw new OidcAuthenticationException("JWT algorithm $algorithm is not supported"),
    };

    if ($algorithm !== $keyAlgorithm->algorithmId()) {
      throw new OidcAuthenticationException('Key algorithm does not match token algorithm');
    }

    return $keyAlgorithm;
  }

  /** @param list<JwkObject> $keys */
  private function getMatchingJwkForToken(array $keys, Token $token): object
  {
    $headers   = $token->headers();
    $algorithm = $headers->get('alg');
    $keyId     = $headers->get('kid');
    $kty       = match (true) {
      str_starts_with((string)$algorithm, 'RS') => 'RSA',
      str_starts_with((string)$algorithm, 'ES') => 'EC',
      default                                   => null,
    };

    foreach ($keys as $key) {
      if ($kty && $key->kty === $kty) {
        if ($keyId === null || $key->kid === $keyId) {
          return $key;
        }
      } else {
        if ($key->alg === $algorithm && $key->kid === $keyId) {
          return $key;
        }
      }
    }

    if ($keyId !== null) {
      throw new OidcAuthenticationException("Unable to find a key for (algorithm, key id): $algorithm, $keyId");
    } else {
      throw new OidcAuthenticationException('Unable to find a signing key');
    }
  }

  /**
   * @throws OidcConfigurationResolveException
   *
   * @return list<JwkObject>
   */
  private function getJwks(string $jwksUri, bool $forceNoCache = false): array
  {
    if (!$jwksUri) {
      throw new OidcAuthenticationException('Unable to verify signature due to no jwks_uri being defined');
    }

    // Only a single uri can be loaded in one instance
    if ($this->jwksUri !== null && $this->jwksUri !== $jwksUri) {
      throw new OidcAuthenticationException('The jwks uri does not match with an earlier invocation');
    }

    // If already loaded, directly return JWK data, but not when no cache has been enforced
    if (!$forceNoCache && $this->jwks !== null) {
      return $this->jwks;
    }

    if ($this->isCacheEnabled()) {
      try {
        $this->cacheKey ??= '_drenso_oidc_client__jwks__' . (new AsciiSlugger('en'))->slug($jwksUri);
        if ($forceNoCache) {
          // Clear the cache item to force refresh
          $this->jwksCache->delete($this->cacheKey);
        }

        $jwks = $this->jwksCache->get($this->cacheKey, function (ItemInterface $item) use ($jwksUri) {
          $item->expiresAfter($this->jwksCacheTime);

          return json_decode($this->urlFetcher->fetchUrl($jwksUri))->keys;
        });
      } catch (InvalidArgumentException $e) {
        throw new OidcConfigurationResolveException('Cache failed: ' . $e->getMessage(), previous: $e);
      }
    } else {
      $jwks = json_decode($this->urlFetcher->fetchUrl($jwksUri))->keys;
    }

    if ($jwks === null) {
      throw new OidcAuthenticationException('Error decoding JSON from jwks_uri');
    }

    $this->jwksUri = $jwksUri;

    return $this->jwks = $jwks;
  }

  private static function urlEncode(string $str): string
  {
    $enc = base64_encode($str);
    $enc = rtrim($enc, '=');

    return strtr($enc, '+/', '-_');
  }

  private function getClock(): ClockInterface
  {
    return $this->clock ??= new class implements ClockInterface {
      public function now(): DateTimeImmutable
      {
        return new DateTimeImmutable();
      }
    };
  }

  /** @phpstan-assert-if-true !null $this->jwksCache */
  public function isCacheEnabled(): bool
  {
    return $this->jwksCache && $this->jwksCacheTime !== null;
  }
}
