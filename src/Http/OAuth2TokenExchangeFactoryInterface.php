<?php

namespace Drenso\OidcBundle\Http;

interface OAuth2TokenExchangeFactoryInterface
{
  public function getAccessToken(): string;
}
