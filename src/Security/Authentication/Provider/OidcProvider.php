<?php

namespace Drenso\OidcBundle\Security\Authentication\Provider;

use Drenso\OidcBundle\Security\Authentication\Token\OidcToken;
use Drenso\OidcBundle\Security\Exception\OidcAuthenticationException;
use Drenso\OidcBundle\Security\Exception\OidcUsernameNotFoundException;
use Drenso\OidcBundle\Security\UserProvider\OidcUserProviderInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;

class OidcProvider implements AuthenticationProviderInterface
{

  /**
   * @var LoggerInterface
   */
  private $logger;
  /**
   * @var TokenStorageInterface
   */
  private $tokenStorage;
  /**
   * @var UserCheckerInterface
   */
  private $userChecker;
  /**
   * @var OidcUserProviderInterface
   */
  private $userProvider;

  public function __construct(OidcUserProviderInterface $userProvider, UserCheckerInterface $userChecker, TokenStorageInterface $tokenStorage, LoggerInterface $logger)
  {
    $this->userProvider = $userProvider;
    $this->userChecker  = $userChecker;
    $this->tokenStorage = $tokenStorage;
    $this->logger       = $logger;
  }

  /**
   * Attempts to authenticate a TokenInterface object.
   *
   * @param TokenInterface $token The TokenInterface instance to authenticate
   *
   * @return TokenInterface An authenticated TokenInterface instance, never null
   *
   * @throws AuthenticationException if the authentication fails
   */
  public function authenticate(TokenInterface $token)
  {
    // Check whether the token is supported
    if (!$this->supports($token)) {
      $this->logger->debug("OIDC Provider: Unsupported token supplied", array('token' => get_class($token)));
      throw new OidcAuthenticationException(OidcAuthenticationException::TOKEN_UNSUPPORTED, $token);
    }
    assert($token instanceof OidcToken);

    // Check if the token is already authenticated
    if ($token->isAuthenticated()) {
      $this->logger->debug("OIDC Provider: Token already authenticated", array('username' => $token->getUsername()));

      return $token;
    }

    // Retrieve the user
    try {
      $user = $this->userProvider->loadUserByToken($token);
    } catch (UsernameNotFoundException $e) {
      $this->logger->debug("OIDC Provider: User not found", array('username' => $token->getUsername()));
      throw new OidcUsernameNotFoundException($e);
    }

    // Check user
    $this->userChecker->checkPreAuth($user);
    $this->userChecker->checkPostAuth($user);

    // Create the authenticated token
    $authData = $token->getAuthData();
    $token = new OidcToken($user->getRoles());
    $token
      ->setAuthData($authData)
      ->setUser($user);

    return $token;
  }

  /**
   * Checks whether this provider supports the given token.
   *
   * @param TokenInterface $token
   *
   * @return bool true if the implementation supports the Token, false otherwise
   */
  public function supports(TokenInterface $token)
  {
    return $token instanceof OidcToken;
  }
}
