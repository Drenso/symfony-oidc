<?php

namespace Drenso\OidcBundle\Model;

use DateTimeImmutable;
use Drenso\OidcBundle\Enum\OidcTokenType;
use Drenso\OidcBundle\Exception\OidcException;
use stdClass;

/**
 * Contains the access and id tokens retrieved from OpenID authentication.
 */
class OidcTokens
{
  private readonly string $accessToken;
  private readonly string $idToken;
  private ?DateTimeImmutable $expiry = null;
  private ?string $refreshToken      = null;
  /** @var string[]|null */
  private ?array $scope = null;

  /** @throws OidcException */
  public function __construct(stdClass $tokens)
  {
    // These are the only required parameters per https://tools.ietf.org/html/rfc6749#section-4.2.2
    if (!isset($tokens->id_token) || !isset($tokens->access_token)) {
      throw new OidcException('Invalid token object.');
    }

    $this->accessToken = $tokens->access_token;
    $this->idToken     = $tokens->id_token;

    if (isset($tokens->expires_in)) {
      $this->expiry = DateTimeImmutable::createFromFormat('U', (string)(time() + $tokens->expires_in));
    }

    if (isset($tokens->refresh_token)) {
      $this->refreshToken = $tokens->refresh_token;
    }

    if (isset($tokens->scope)) {
      $this->scope = explode(' ', (string)$tokens->scope);
    }
  }

  public function getAccessToken(): string
  {
    return $this->accessToken;
  }

  public function getExpiry(): ?DateTimeImmutable
  {
    return $this->expiry;
  }

  public function getIdToken(): string
  {
    return $this->idToken;
  }

  public function getRefreshToken(): ?string
  {
    return $this->refreshToken;
  }

  public function getTokenByType(OidcTokenType $type): ?string
  {
    return match ($type) {
      OidcTokenType::ID      => $this->idToken,
      OidcTokenType::ACCESS  => $this->accessToken,
      OidcTokenType::REFRESH => $this->refreshToken,
    };
  }

  /**  @return string[]|null */
  public function getScope(): ?array
  {
    return $this->scope;
  }
}
