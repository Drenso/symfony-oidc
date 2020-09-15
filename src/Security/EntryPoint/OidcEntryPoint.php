<?php

namespace Drenso\OidcBundle\Security\EntryPoint;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;

class OidcEntryPoint implements AuthenticationEntryPointInterface
{
  private $loginPath;
  private $httpUtils;

  /**
   * @param HttpUtils $httpUtils
   * @param string    $loginPath The path to the login form
   */
  public function __construct(HttpUtils $httpUtils, string $loginPath)
  {
    $this->httpUtils = $httpUtils;
    $this->loginPath = $loginPath;
  }

  /**
   * {@inheritdoc}
   */
  public function start(Request $request, AuthenticationException $authException = null)
  {
    return $this->httpUtils->createRedirectResponse($request, $this->loginPath);
  }
}
