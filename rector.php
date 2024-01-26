<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Php73\Rector\FuncCall\JsonThrowOnErrorRector;
use Rector\PostRector\Rector\NameImportingPostRector;
use Rector\Set\ValueObject\LevelSetList;
use Rector\ValueObject\PhpVersion;

return static function (RectorConfig $rc): void {
  $rc->paths(['./src']);
  $rc->importNames();
  $rc->phpVersion(PhpVersion::PHP_80);
  $rc->skip([
    JsonThrowOnErrorRector::class,
    NameImportingPostRector::class => [
      './src/OidcClient.php',
    ],
  ]);

  $rc->import(LevelSetList::UP_TO_PHP_80);
};
