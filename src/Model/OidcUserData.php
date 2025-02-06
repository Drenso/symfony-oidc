<?php

namespace Drenso\OidcBundle\Model;

use stdClass;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\PropertyAccess\PropertyAccessorInterface;

class OidcUserData
{
  private static ?PropertyAccessorInterface $accessor = null;
  private readonly stdClass $userData;

  /** @param array<string, mixed> $userData */
  public function __construct(array $userData)
  {
    // Cast the array data to a stdClass for easy access
    $this->userData = (object)$userData;
  }

  /** Get the OIDC sub claim */
  public function getSub(): string
  {
    return $this->getUserDataString('sub');
  }

  /** Get the OIDC preferred_username claim */
  public function getDisplayName(): string
  {
    return $this->getUserDataString('preferred_username');
  }

  /** Get the OIDC family_name claim */
  public function getFamilyName(): string
  {
    return $this->getUserDataString('family_name');
  }

  /** Get the OIDC name claim */
  public function getFullName(): string
  {
    return $this->getUserDataString('name');
  }

  /** Get the OIDC given_name claim */
  public function getGivenName(): string
  {
    return $this->getUserDataString('given_name');
  }

  /** Get the OIDC email claim */
  public function getEmail(): string
  {
    return $this->getUserDataString('email');
  }

  /** Get the OIDC email verified claim */
  public function getEmailVerified(): bool
  {
    return $this->getUserDataBoolean('email_verified');
  }

  /** Get the OIDC schac_home_organization claim */
  public function getOrganisation(): string
  {
    return $this->getUserDataString('schac_home_organization');
  }

  /**
   * Get the OIDC edu_person_affiliations claim.
   *
   * @return string[]
   */
  public function getAffiliations(): array
  {
    return $this->getUserDataArray('eduperson_affiliation');
  }

  /**
   * Get the OIDC uids claim.
   *
   * @return string[]
   */
  public function getUids(): array
  {
    return $this->getUserDataArray('uids');
  }

  /** Get a boolean property from the user data */
  public function getUserDataBoolean(string $key): bool
  {
    return $this->getUserData($key) ?: false;
  }

  /** Get a string property from the user data */
  public function getUserDataString(string $key): string
  {
    return $this->getUserData($key) ?: '';
  }

  /**
   * Get an array property from the user data.
   *
   * @phpstan-ignore missingType.iterableValue
   */
  public function getUserDataArray(string $key): array
  {
    return $this->getUserData($key) ?: [];
  }

  public function getUserData(string $propertyPath): mixed
  {
    self::$accessor ??= PropertyAccess::createPropertyAccessorBuilder()
      ->disableExceptionOnInvalidIndex()
      ->disableExceptionOnInvalidPropertyPath()
      ->getPropertyAccessor();

    // Cast the user data to a stdClass
    return self::$accessor->getValue($this->userData, $propertyPath);
  }
}
