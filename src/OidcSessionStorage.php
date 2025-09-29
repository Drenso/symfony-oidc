<?php

namespace Drenso\OidcBundle;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class OidcSessionStorage
{
  public function __construct(private readonly RequestStack $requestStack, private readonly string $clientName)
  {
  }

  public function clearNonce(): void
  {
    $this->getSession()->remove($this->nonceKey());
  }

  public function clearCodeVerifier(): void
  {
    $this->getSession()->remove($this->codeVerifierKey());
  }

  public function clearRememberMe(): void
  {
    $this->getSession()->remove($this->rememberKey());
  }

  public function clearState(): void
  {
    $this->getSession()->remove($this->stateKey());
  }

  public function getNonce(): ?string
  {
    return $this->getSession()->get($this->nonceKey());
  }

  public function getCodeVerifier(): ?string
  {
    return $this->getSession()->get($this->codeVerifierKey());
  }

  public function getRememberMe(): bool
  {
    return $this->getSession()->get($this->rememberKey()) ?? false;
  }

  public function getState(): ?string
  {
    return $this->getSession()->get($this->stateKey());
  }

  public function storeNonce(string $value): void
  {
    $this->getSession()->set($this->nonceKey(), $value);
  }

  public function storeCodeVerifier(string $value): void
  {
    $this->getSession()->set($this->codeVerifierKey(), $value);
  }

  public function storeRememberMe(bool $value): void
  {
    $this->getSession()->set($this->rememberKey(), $value);
  }

  public function storeState(string $value): void
  {
    $this->getSession()->set($this->stateKey(), $value);
  }

  private function getSession(): SessionInterface
  {
    return $this->requestStack->getSession();
  }

  private function codeVerifierKey(): string
  {
    return 'drenso.oidc.session.code_verifier.' . $this->clientName;
  }

  private function nonceKey(): string
  {
    return 'drenso.oidc.session.nonce.' . $this->clientName;
  }

  private function rememberKey(): string
  {
    return 'drenso.oidc.session.remember_me.' . $this->clientName;
  }

  private function stateKey(): string
  {
    return 'drenso.oidc.session.state.' . $this->clientName;
  }

  private function accessTokenKey(): string
  {
    return 'drenso.oidc.session.access_token.' . $this->clientName;
  }

  public function getAccessToken(): ?string
  {
    return $this->getSession()->get($this->accessTokenKey());
  }

  public function storeAccessToken(string $value): void
  {
    $this->getSession()->set($this->accessTokenKey(), $value);
  }
}
