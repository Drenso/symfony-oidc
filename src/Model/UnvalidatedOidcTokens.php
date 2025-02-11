<?php

namespace Drenso\OidcBundle\Model;

use DateTimeImmutable;
use Drenso\OidcBundle\Enum\OidcTokenType;
use RuntimeException;
use stdClass;

/** Contains the unvalidated access and id tokens retrieved from the identity provider. */
class UnvalidatedOidcTokens
{
  protected readonly ?string $accessToken;
  protected readonly ?string $idToken;
  private ?DateTimeImmutable $expiry = null;
  private ?string $refreshToken      = null;
  /** @var string[]|null */
  private ?array $scope = null;

  public function __construct(self|stdClass $tokens)
  {
    if ($tokens instanceof self) {
      $this->accessToken  = $tokens->accessToken;
      $this->idToken      = $tokens->idToken;
      $this->expiry       = $tokens->expiry ? DateTimeImmutable::createFromInterface($tokens->expiry) : null;
      $this->refreshToken = $tokens->refreshToken;
      $this->scope        = $tokens->scope;

      return;
    }

    $this->accessToken = $tokens->access_token ?? null;
    $this->idToken     = $tokens->id_token ?? null;

    if (isset($tokens->expires_in)) {
      $this->expiry = DateTimeImmutable::createFromFormat('U', (string)(time() + $tokens->expires_in))
        ?: throw new RuntimeException('Failed to generate expiry');
    }

    if (isset($tokens->refresh_token)) {
      $this->refreshToken = $tokens->refresh_token;
    }

    if (isset($tokens->scope)) {
      $this->scope = explode(' ', (string)$tokens->scope);
    }
  }

  public function getAccessToken(): ?string
  {
    return $this->accessToken;
  }

  public function getExpiry(): ?DateTimeImmutable
  {
    return $this->expiry;
  }

  public function getIdToken(): ?string
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
