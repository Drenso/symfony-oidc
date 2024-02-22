<?php

declare(strict_types=1);

use Rector\Caching\ValueObject\Storage\FileCacheStorage;
use Rector\Config\RectorConfig;
use Rector\Php73\Rector\FuncCall\JsonThrowOnErrorRector;
use Rector\PostRector\Rector\NameImportingPostRector;

return RectorConfig::configure()
  ->withCache('./var/cache/rector', FileCacheStorage::class)
  ->withPaths(['./src'])
  ->withParallel(timeoutSeconds: 180, jobSize: 10)
  ->withImportNames()
  ->withPhpSets()
  ->withSkip([
    JsonThrowOnErrorRector::class,
    NameImportingPostRector::class => [
      './src/OidcClient.php',
    ],
  ]);
