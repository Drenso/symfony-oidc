<?php

namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Security\Exception\OidcAuthenticationException;

/** Helper for resource loading. */
class OidcUrlFetcher
{
  /**
   * @param string[]             $customClientHeaders
   * @param array<string, mixed> $customClientOptions
   */
  public function __construct(
    private readonly array $customClientHeaders = [],
    private readonly array $customClientOptions = [],
  ) {
  }

  /**
   * Retrieve the content from the specified url.
   *
   * @param non-empty-string          $url
   * @param array<string, mixed>|null $params  if this is set the request type will be POST
   * @param string[]                  $headers extra headers to be sent with the request
   */
  public function fetchUrl(string $url, ?array $params = null, array $headers = []): string
  {
    // Create a new cURL resource handle
    $ch = curl_init();

    // Determine whether this is a GET or POST
    if ($params !== null) {
      $params = http_build_query($params);

      // Allows to keep the POST method even after redirect
      curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
      curl_setopt($ch, CURLOPT_POSTFIELDS, $params);

      // Add POST-specific headers
      $headers[] = 'Content-Type: application/x-www-form-urlencoded';
      $headers[] = 'Content-Length: ' . strlen($params);
    }

    // Add a User-Agent header to prevent firewall blocks
    $curlVersion = (curl_version() ?: [])['version'] ?? 'unknown';
    $headers[]   = "User-Agent: curl/$curlVersion drenso/symfony-oidc";

    // Add custom headers to existing headers
    $headers = array_merge($headers, $this->customClientHeaders);

    // Include headers
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    // Set URL to download
    curl_setopt($ch, CURLOPT_URL, $url);

    // Include header in result?
    curl_setopt($ch, CURLOPT_HEADER, false);

    // Allows following redirects
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

    // Setup certificate checking
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);

    // Should cURL return or print out the data? (true = return, false = print)
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    // Timeout in seconds
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);

    foreach ($this->customClientOptions as $opt => $value) {
      curl_setopt($ch, $opt, $value);
    }

    // Download the given URL, and return output
    $output = curl_exec($ch);

    if ($output === false) {
      throw new OidcAuthenticationException('Curl error: ' . curl_error($ch));
    }

    return $output;
  }
}
