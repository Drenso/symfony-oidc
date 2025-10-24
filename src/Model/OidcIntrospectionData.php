<?php

namespace Drenso\OidcBundle\Model;

use stdClass;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\PropertyAccess\PropertyAccessorInterface;

class OidcIntrospectionData
{
  private static ?PropertyAccessorInterface $accessor = null;
  private readonly stdClass $introspectionData;
  /** @var array<string, mixed> */
  private readonly array $introspectionDataArray;

  /** @param array<string, mixed> $introspectionData */
  public function __construct(array $introspectionData)
  {
    // Cast the array data to a stdClass for easy access
    $this->introspectionData      = (object)$introspectionData;
    $this->introspectionDataArray = $introspectionData;
  }

  public function isActive(): bool
  {
    return $this->getIntrospectionDataBoolean('active');
  }

  /** Get the OIDC scope claim */
  public function getScope(): string
  {
    return $this->getIntrospectionDataString('scope');
  }

  /** Get the OIDC client_id claim */
  public function getClientId(): string
  {
    return $this->getIntrospectionDataString('client_id');
  }

  /** Get the OIDC username claim */
  public function getUsername(): string
  {
    return $this->getIntrospectionDataString('username');
  }

  /** Get the OIDC token_type claim */
  public function getTokenType(): string
  {
    return $this->getIntrospectionDataString('token_type');
  }

  /** Get the OIDC exp claim */
  public function getExp(): ?int
  {
    return $this->getIntrospectionDataInteger('exp');
  }

  /** Get the OIDC iat claim */
  public function getIat(): ?int
  {
    return $this->getIntrospectionDataInteger('iat');
  }

  /** Get the OIDC nbf claim */
  public function getNbf(): ?int
  {
    return $this->getIntrospectionDataInteger('nbf');
  }

  /** Get the OIDC sub claim */
  public function getSub(): string
  {
    return $this->getIntrospectionDataString('sub');
  }

  /**
   * Get the OIDC aud claim.
   *
   * @return string|string[]
   */
  public function getAud(): string|array
  {
    return $this->getIntrospectionDataStringOrArray('aud');
  }

  /** Get the OIDC iss claim */
  public function getIss(): string
  {
    return $this->getIntrospectionDataString('iss');
  }

  /** Get the OIDC jti claim */
  public function getJti(): string
  {
    return $this->getIntrospectionDataString('jti');
  }

  /** Get a boolean property from the introspection data */
  public function getIntrospectionDataBoolean(string $key): bool
  {
    return $this->getIntrospectionData($key) ?: false;
  }

  /** Get a string property from the introspection data */
  public function getIntrospectionDataString(string $key): string
  {
    return $this->getIntrospectionData($key) ?: '';
  }

  /**
   * Get a string property from the introspection data.
   *
   * @return string|string[]
   */
  public function getIntrospectionDataStringOrArray(string $key): string|array
  {
    return $this->getIntrospectionData($key) ?: '';
  }

  /** Get a integer property from the introspection data */
  public function getIntrospectionDataInteger(string $key): ?int
  {
    return $this->getIntrospectionData($key) ?: null;
  }

  public function getIntrospectionData(string $propertyPath): mixed
  {
    self::$accessor ??= PropertyAccess::createPropertyAccessorBuilder()
      ->disableExceptionOnInvalidIndex()
      ->disableExceptionOnInvalidPropertyPath()
      ->getPropertyAccessor();

    // Cast the introspection data to a stdClass
    return self::$accessor->getValue($this->introspectionData, $propertyPath);
  }

  /** @return array<string, mixed> */
  public function getIntrospectionDataArray(): array
  {
    return $this->introspectionDataArray;
  }
}
