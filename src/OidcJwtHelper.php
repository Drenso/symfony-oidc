<?php

namespace Drenso\OidcBundle;

use DateInterval;
use DateTimeImmutable;
use Drenso\OidcBundle\Enum\OidcTokenType;
use Drenso\OidcBundle\Exception\OidcConfigurationResolveException;
use Drenso\OidcBundle\Model\OidcTokens;
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
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use phpseclib3\Crypt\PublicKeyLoader;
use Psr\Cache\InvalidArgumentException;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\String\Slugger\AsciiSlugger;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Contains helper functions to decode/verify JWT data.
 */
class OidcJwtHelper
{
  private static ?ParserInterface $parser = null;
  private static ?Validator $validator    = null;

  protected ?array $jwks     = null;
  protected ?string $jwksUri = null;
  private ?string $cacheKey  = null;

  public function __construct(
    protected readonly ?CacheInterface $jwksCache,
    protected ?ClockInterface $clock,
    protected readonly OidcUrlFetcher $urlFetcher,
    protected readonly OidcSessionStorage $sessionStorage,
    protected readonly string $clientId,
    protected readonly ?int $jwksCacheTime,
    protected readonly int $leewaySeconds)
  {
  }

  public static function parseToken(string $token): UnencryptedToken
  {
    $parsedToken = (self::$parser ??= new Parser(new JoseEncoder()))->parse($token);

    /** @noinspection PhpConditionAlreadyCheckedInspection */
    if (!$parsedToken instanceof UnencryptedToken) {
      throw new RuntimeException('Not an unencrypted token.');
    }

    return $parsedToken;
  }

  /**
   * Validate the supplied OidcTokens.
   *
   * @throws OidcConfigurationResolveException Thrown when the cache fails
   * @throws OidcAuthenticationException       Throw when a token is invalid
   */
  public function verifyTokens(string $issuer, string $jwksUri, OidcTokens $tokens, bool $verifyNonce): void
  {
    // Only validate id and access tokens
    $idToken     = $tokens->getTokenByType(OidcTokenType::ID);
    $accessToken = $tokens->getTokenByType(OidcTokenType::ACCESS);

    $this->verifyToken($issuer, $jwksUri, OidcTokenType::ID, $idToken, $verifyNonce, $accessToken);
    $this->verifyToken($issuer, $jwksUri, OidcTokenType::ACCESS, $accessToken, $verifyNonce);
  }

  /**
   * Validate a token.
   *
   * @throws OidcConfigurationResolveException Thrown when the cache fails
   * @throws OidcAuthenticationException       Throw when a token is invalid
   */
  public function verifyToken(
    string $issuer,
    string $jwksUri,
    OidcTokenType $tokenType,
    string $token,
    bool $verifyNonce,
    ?string $accessToken = null,
    Constraint ...$additionalConstraints): void
  {
    self::$validator ??= new Validator();

    // Parse the token
    $token  = self::parseToken($token);
    $signer = $this->getTokenSigner($token);
    $key    = $this->getTokenKey($jwksUri, $token);

    if (!self::$validator->validate($token, new SignedWith($signer, $key))) {
      throw new OidcAuthenticationException('Unable to verify signature');
    }

    // Default claims
    $constraints = [
      new IssuedBy($issuer),
      new LooseValidAt($this->getClock(), new DateInterval("PT{$this->leewaySeconds}S")),
    ];

    if ($tokenType === OidcTokenType::ID) {
      $constraints[] = new PermittedFor($this->clientId);

      if ($token->claims()->has('at_hash') && $accessToken) {
        // Validate the at (access token) hash
        $bit = substr((string)$token->headers()->get('alg'), 2, 3);
        if (!$bit || !is_numeric($bit)) {
          throw new OidcAuthenticationException('Could not determine at hash algorithm');
        }

        $constraints[] = new HasClaimWithValue(
          'at_hash',
          self::urlEncode(
            substr(hash("sha$bit", $accessToken, true), 0, (int)$bit / 16),
          ),
        );
      }

      if ($verifyNonce) {
        $constraints[] = new HasClaimWithValue('nonce', $this->sessionStorage->getNonce());
        $this->sessionStorage->clearNonce();
      }
    }

    if (!self::$validator->validate($token, ...$constraints)) {
      throw new OidcAuthenticationException('Unable to verify JWT claims');
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

  /** @throws OidcConfigurationResolveException */
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
    return $this->clock ??= new class() implements ClockInterface {
      public function now(): DateTimeImmutable
      {
        return new DateTimeImmutable();
      }
    };
  }

  public function isCacheEnabled(): bool
  {
    return $this->jwksCache && $this->jwksCacheTime !== null;
  }
}
