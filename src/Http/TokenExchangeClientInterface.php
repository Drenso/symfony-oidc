<?php

namespace Drenso\OidcBundle\Http;

interface TokenExchangeClientInterface
{
  public function getExchangedAccessToken(): string;
}
