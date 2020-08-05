<?php

namespace Drenso\OidcBundle\Security\Authentication\Token;

use Drenso\OidcBundle\OidcTokens;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class OidcToken extends AbstractToken
{

  /**
   * @var array
   */
  private $userData;

  /**
   * OidcToken constructor.
   *
   * @param array $roles
   */
  public function __construct(array $roles = array())
  {
    parent::__construct($roles);

    $this->setAuthenticated(count($roles) > 0);
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
    $this->userData = $userData;

    return $this;
  }

  /**
   * Set the auth data from the OIDC response.
   *
   * @return OidcToken
   */
  public function setAuthData(OidcTokens $authData): self
  {
    $this->setAttribute('authData', $authData);

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
    if (array_key_exists($key, $this->userData)) {
      return $this->userData[$key];
    }

    return NULL;
  }

  /**
   * Get auth data - OIDC tokens, scope and expiry.
   */
  public function getAuthData(): OidcTokens
  {
    return $this->getAttribute('authData');
  }
}
