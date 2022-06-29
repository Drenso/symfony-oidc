<?php

/**
 * This configuration will be read and overlayed on top of the
 * default configuration. Command line arguments will be applied
 * after this file is read.
 *
 * @see src/Phan/Config.php
 * @see https://github.com/etsy/phan/blob/master/.phan/config.php
 * See Config for all configurable options.
 *
 * A Note About Paths
 * ==================
 *
 * Files referenced from this file should be defined as
 *
 * ```
 *   Config::projectPath('relative_path/to/file')
 * ```
 *
 * where the relative path is relative to the root of the
 * project which is defined as either the working directory
 * of the phan executable or a path passed in via the CLI
 * '-d' flag.
 */

/**
 * Runs glob recursivly on a specified directory, and returns all files that conform to the given glob.
 *
 * @param string $pattern
 * @param int    $flags
 *
 * @return array
 */

function rglob($pattern, $flags = 0)
{
  $files = glob($pattern, $flags);
  foreach (glob(dirname($pattern) . '/*', GLOB_ONLYDIR | GLOB_NOSORT) as $dir) {
    $files = array_merge($files, rglob($dir . '/' . basename($pattern), $flags));
  }

  return $files;
}

//Disables analysis on the cache, all vendor code, the code for HTMLDiff (non-composer dependency) and all Traits (done via rglob).
$disabled_analysis = array_merge(
    [
        'vendor',
    ],
    rglob('src/*Trait*')
);


return [
  // If true, missing properties will be created when they are first seen. If false, we'll report an error message.
    "allow_missing_properties"        => false,

  // Allow null to be cast as any type and for any type to be cast to null.
    "null_casts_as_any_type"          => true,

  // Backwards Compatibility Checking
    'backward_compatibility_checks'   => false,

  // Run a quick version of checks that takes less time
    "quick_mode"                      => false,

  // Only emit normal severity issues
    "minimum_severity"                => 5,

  // A set of fully qualified class-names for which
  // a call to parent::__construct() is required
    'parent_constructor_required'     => [],

  // A list of plugin files to execute
    'plugins'                         => [
        'vendor/drenso/phan-extensions/Plugin/Annotation/SymfonyAnnotationPlugin.php',
        'vendor/drenso/phan-extensions/Plugin/DocComment/ThrowsPlugin.php',
        'vendor/drenso/phan-extensions/Plugin/DocComment/MethodPlugin.php',
        'vendor/drenso/phan-extensions/Plugin/DocComment/InlineVarPlugin.php',
    ],

  // A list of directories that should be parsed for class and
  // method information. After excluding the directories
  // defined in exclude_analysis_directory_list, the remaining
  // files will be statically analyzed for errors.
  //
  // Thus, both first-party and third-party code being used by
  // your application should be included in this list.
    'directory_list'                  => [
        'src',
        'vendor',
    ],

  // A list of directories holding code that we want to parse, but not analyze
    "exclude_analysis_directory_list" => $disabled_analysis,

  // A file list that defines files that will be excluded
  // from parsing and analysis and will not be read at all.

  // This is useful for excluding hopelessly unanalyzable
  // files that can't be removed for whatever reason.
    'exclude_file_list'               => [
        'vendor/rector/rector/stubs-rector/Internal/EnumInterfaces.php',
        'vendor/symfony/symfony/src/Symfony/Component/Intl/Resources/stubs/IntlDateFormatter.php',
    ],
];
