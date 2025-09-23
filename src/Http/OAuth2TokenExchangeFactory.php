<?php

namespace Drenso\OidcBundle\Http;

use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\Model\AccessTokens;
use Drenso\OidcBundle\OidcClient;
use Drenso\OidcBundle\OidcSessionStorage;
use Psr\Cache\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Symfony\Component\String\Slugger\AsciiSlugger;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class OAuth2TokenExchangeFactory implements OAuth2TokenExchangeFactoryInterface
{
  public function __construct(
    private readonly ?OidcSessionStorage $sessionStorage,
    private readonly OidcClient $oidcClient,
    private readonly string $scope,
    private readonly string $audience,
    private readonly LoggerInterface $logger,
    private readonly ?CacheInterface $cache = null,
    private readonly int $cacheTime = 3600,
  ) {
  }

  /** @throws OidcException */
  public function getAccessToken(): string
  {
    return $this->getExchangedTokensWithCaching()->getAccessToken();
  }

  private function getExchangedTokensWithCaching(): AccessTokens
  {
    $originalToken = $this->sessionStorage->getAccessToken();

    // Exchange the original access token for one with the target scope/audience
    // Create a cache key based on the original token, scope, and audience
    $cacheKey = $this->generateCacheKey($originalToken, $this->scope, $this->audience);

    if ($this->isCacheEnabled()) {
      try {
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
        $this->logger->error($e->getMessage(), ['exception' => $e]);
        // If cache fails, fall back to direct token exchange
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
      '_drenso_oidc_http_client_factory__token_exchange__%s__%s__%s__%s',
      $slugger->slug($scope),
      $slugger->slug($audience),
      $tokenHash,
      substr($tokenHash, 0, 8)
    );
  }

  private function isCacheEnabled(): bool
  {
    return $this->cache !== null && $this->cacheTime !== null;
  }
}
