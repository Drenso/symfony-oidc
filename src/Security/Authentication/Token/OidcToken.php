<?php

namespace Drenso\OidcBundle\Security\Authentication\Token;

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
   * @return string
   */
  public function getDisplayName() : string
  {
    return $this->getUserDataString('preferred_username');
  }

  /**
   * @return string
   */
  public function getFamilyName() : string
  {
    return $this->getUserDataString('family_name');
  }

  /**
   * @return string
   */
  public function getFullName() : string
  {
    return $this->getUserDataString('name');
  }

  /**
   * @return string
   */
  public function getGivenName() : string
  {
    return $this->getUserDataString('given_name');
  }

  /**
   * @return string
   */
  public function getUsername() : string
  {
    if ($this->getUser() !== NULL) {
      return parent::getUsername();
    }

    return $this->getUserDataString('email');
  }

  /**
   * @return array
   */
  public function getAffiliations() : array
  {
    return $this->getUserDataArray('edu_person_affiliations');
  }

  /**
   * @return array
   */
  public function getUids() : array
  {
    return $this->getUserDataArray('uids');
  }

  /**
   * @param $userData
   *
   * @return OidcToken
   */
  public function setUserData(array $userData)
  {
    $this->userData = $userData;

    return $this;
  }

  /**
   * @param string $key
   *
   * @return string
   */
  private function getUserDataString(string $key) : string
  {
    if (array_key_exists($key, $this->userData)) {
      return $this->userData[$key];
    }

    return '';
  }

  /**
   * @param string $key
   *
   * @return array
   */
  private function getUserDataArray(string $key) : array
  {
    if (array_key_exists($key, $this->userData)){
      return $this->userData[$key];
    }

    return [];
  }
}
