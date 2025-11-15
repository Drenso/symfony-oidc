<?php

namespace Drenso\OidcBundle\Http;

use Drenso\OidcBundle\Exception\OidcConfigurationResolveException;
use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\Model\AccessTokens;
use Drenso\OidcBundle\OidcClient;
use Drenso\OidcBundle\OidcSessionStorage;
use Psr\Cache\InvalidArgumentException;
use Symfony\Component\String\Slugger\AsciiSlugger;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class TokenExchangeClient implements TokenExchangeClientInterface
{
  public function __construct(
    private readonly OidcClient $oidcClient,
    private readonly ?OidcSessionStorage $sessionStorage,
    private readonly string $scope,
    private readonly string $audience,
    private readonly ?CacheInterface $cache = null,
    private readonly int $cacheTime = 3600,
  ) {
  }

  /** @throws OidcException */
  public function getExchangedAccessToken(): string
  {
    return $this->getExchangedTokensWithCaching()->getAccessToken();
  }

  /**
   * @throws OidcConfigurationResolveException
   * @throws OidcException
   */
  private function getExchangedTokensWithCaching(): AccessTokens
  {
    if ($this->sessionStorage === null) {
      throw new OidcException('Session storage is not available');
    }
    $originalToken = $this->sessionStorage->getAccessToken();

    if ($originalToken === null) {
      throw new OidcException('No access token available in session');
    }

    if ($this->isCacheEnabled() && $this->cache !== null) {
      try {
        // Create a cache key based on the original token, scope, and audience
        $cacheKey = $this->generateCacheKey($originalToken, $this->scope, $this->audience);

        return $this->cache->get($cacheKey, function (ItemInterface $item) use ($originalToken) {
          // Exchange the original token for one with target scope/audience
          $tokens = $this->exchangeTokens($originalToken);
          // Set cache expiry based on the token's actual expiry time
          $expiry = $tokens->getExpiry();
          if ($expiry) {
            $item->expiresAt($expiry);
          } else {
            $item->expiresAfter($this->cacheTime);
          }

          return $tokens;
        });
      } catch (InvalidArgumentException $e) {
        throw new OidcConfigurationResolveException('Cache failed: ' . $e->getMessage(), previous: $e);
      }
    }

    return $this->exchangeTokens($originalToken);
  }

  /** @throws OidcException */
  private function exchangeTokens(string $accessToken): AccessTokens
  {
    return $this->oidcClient->exchangeTokens(
      accessToken: $accessToken,
      targetScope: $this->scope,
      targetAudience: $this->audience,
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token'
    );
  }

  private function generateCacheKey(string $accessToken, string $scope, string $audience): string
  {
    $slugger   = new AsciiSlugger('en');
    $tokenHash = hash('sha256', $accessToken);

    return sprintf(
      '_drenso_oidc_http_client__token_exchange__%s__%s__%s__%s',
      $slugger->slug($scope),
      $slugger->slug($audience),
      $tokenHash,
      substr($tokenHash, 0, 8)
    );
  }

  private function isCacheEnabled(): bool
  {
    return $this->cache !== null && $this->cacheTime > 0;
  }
}
