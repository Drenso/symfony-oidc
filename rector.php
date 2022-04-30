<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Core\ValueObject\PhpVersion;

return static function (RectorConfig $rc): void {
  $rc->paths([__DIR__ . '/src']);
  $rc->importNames();
  $rc->phpVersion(PhpVersion::PHP_80);
};
