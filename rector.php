<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Core\ValueObject\PhpVersion;
use Rector\Php56\Rector\FunctionLike\AddDefaultValueForUndefinedVariableRector;
use Rector\Php73\Rector\FuncCall\JsonThrowOnErrorRector;
use Rector\Set\ValueObject\LevelSetList;

return static function (RectorConfig $rc): void {
  $rc->paths([__DIR__ . '/src']);
  $rc->importNames();
  $rc->phpVersion(PhpVersion::PHP_80);
  $rc->skip([
      AddDefaultValueForUndefinedVariableRector::class,
      JsonThrowOnErrorRector::class,
  ]);

  $rc->import(LevelSetList::UP_TO_PHP_80);
};
