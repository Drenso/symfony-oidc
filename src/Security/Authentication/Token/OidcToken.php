<?php

namespace Drenso\OidcBundle\Security\Authentication\Token;

use Drenso\OidcBundle\Model\OidcTokens;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class OidcToken extends AbstractToken
{
  private const USER_DATA_ATTR = 'user_data';
  private const AUTH_DATA_ATTR = 'auth_data';

  /**
   * OidcToken constructor.
   *
   * @param array          $roles
   * @param OidcToken|null $other Supply another token to duplicate user/auth data from
   */
  public function __construct(array $roles = [], self $other = NULL)
  {
    parent::__construct($roles);

    $this->setAuthenticated(count($roles) > 0);

    if ($other) {
      $this->setAttribute(self::USER_DATA_ATTR, $other->getAttribute(self::USER_DATA_ATTR));
      $this->setAttribute(self::AUTH_DATA_ATTR, $other->getAttribute(self::AUTH_DATA_ATTR));
    } else {
      $this->setAttribute(self::USER_DATA_ATTR, []);
      $this->setAttribute(self::AUTH_DATA_ATTR, NULL);
    }
  }

  /**
   * Returns the user credentials.
   *
   * @return mixed The user credentials
   */
  public function getCredentials()
  {
    // No credentials available here
    return NULL;
  }

  /**
   * Get the OIDC sub claim
   *
   * @return string
   */
  public function getSub(): string
  {
    return $this->getUserDataString('sub');
  }

  /**
   * Get the OIDC preferred_username claim
   *
   * @return string
   */
  public function getDisplayName(): string
  {
    return $this->getUserDataString('preferred_username');
  }

  /**
   * Get the OIDC family_name claim
   *
   * @return string
   */
  public function getFamilyName(): string
  {
    return $this->getUserDataString('family_name');
  }

  /**
   * Get the OIDC name claim
   *
   * @return string
   */
  public function getFullName(): string
  {
    return $this->getUserDataString('name');
  }

  /**
   * Get the OIDC given_name claim
   *
   * @return string
   */
  public function getGivenName(): string
  {
    return $this->getUserDataString('given_name');
  }

  /**
   * Get the OIDC email claim, when the user is not available in the token.
   * When the user is available, get the username from the user object.
   *
   * @return string
   *
   * @phan-suppress PhanParamSignatureMismatch
   */
  public function getUsername(): string
  {
    if ($this->getUser() !== NULL) {
      return parent::getUsername();
    }

    return $this->getUserDataString('email');
  }

  /**
   * Get the OIDC email claim
   *
   * @return string
   */
  public function getEmail(): string
  {
    return $this->getUserDataString('email');
  }

  /**
   * @return bool
   */
  public function getEmailVerified(): bool
  {
    return $this->getUserDataBoolean('email_verified');
  }

  /**
   * Get the OIDC schac_home_organization claim
   *
   * @return string
   */
  public function getOrganisation(): string
  {
    return $this->getUserDataString('schac_home_organization');
  }

  /**
   * Get the OIDC edu_person_affiliations claim
   *
   * @return array
   */
  public function getAffiliations(): array
  {
    return $this->getUserDataArray('eduperson_affiliation');
  }

  /**
   * Get the OIDC uids claim
   *
   * @return array
   */
  public function getUids(): array
  {
    return $this->getUserDataArray('uids');
  }

  /**
   * Set the user data from the OIDC response
   *
   * @param array $userData
   *
   * @return OidcToken
   */
  public function setUserData(array $userData): self
  {
    $this->setAttribute(self::USER_DATA_ATTR, $userData);

    return $this;
  }

  /**
   * Get a boolean property from the user data
   *
   * @param string $key
   *
   * @return bool
   */
  public function getUserDataBoolean(string $key): bool
  {
    return $this->getUserData($key) ?: false;
  }

  /**
   * Get a string property from the user data
   *
   * @param string $key
   *
   * @return string
   */
  public function getUserDataString(string $key): string
  {
    return $this->getUserData($key) ?: '';
  }

  /**
   * Get an array property from the user data
   *
   * @param string $key
   *
   * @return array
   */
  public function getUserDataArray(string $key): array
  {
    return $this->getUserData($key) ?: [];
  }

  /**
   * @param string $key
   *
   * @return mixed|null
   */
  public function getUserData(string $key)
  {
    $userData = $this->getAttribute(self::USER_DATA_ATTR);
    if (array_key_exists($key, $userData)) {
      return $userData[$key];
    }

    return NULL;
  }

  /**
   * Set the auth data from the OIDC response.
   *
   * @param OidcTokens|null $authData
   *
   * @return OidcToken
   */
  public function setAuthData(?OidcTokens $authData): self
  {
    $this->setAttribute(self::AUTH_DATA_ATTR, $authData);

    return $this;
  }

  /**
   * Get auth data - OIDC tokens, scope and expiry.
   * Might not be set if you created this token yourself
   */
  public function getAuthData(): ?OidcTokens
  {
    return $this->getAttribute(self::AUTH_DATA_ATTR);
  }
}
