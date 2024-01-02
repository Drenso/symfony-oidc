<?php

return (new PhpCsFixer\Config())
  ->setIndent('  ')
  ->setRules([
    '@Symfony'               => true,
    'array_indentation'      => true,
    'binary_operator_spaces' => [
      'default'   => 'align',
      'operators' => [
        '=>'  => 'align_single_space_minimal',
        '|'   => 'no_space',
        '+'   => 'single_space',
        '-'   => 'single_space',
        '*'   => 'single_space',
        '/'   => 'single_space',
        '??'  => 'single_space',
        '||'  => 'single_space',
        '&&'  => 'single_space',
        '===' => 'single_space',
        '=='  => 'single_space',
        '!==' => 'single_space',
        '!='  => 'single_space',
        '<'   => 'single_space',
        '<='  => 'single_space',
        '>'   => 'single_space',
        '>='  => 'single_space',
      ],
    ],
    'cast_spaces'                                      => ['space' => 'none'],
    'class_attributes_separation'                      => ['elements' => ['const' => 'only_if_meta']],
    'concat_space'                                     => ['spacing' => 'one'],
    'global_namespace_import'                          => ['import_classes' => true],
    'increment_style'                                  => false,
    'method_chaining_indentation'                      => true,
    'nullable_type_declaration_for_default_null_value' => true,
    'ordered_imports'                                  => ['imports_order' => ['class', 'function', 'const']],
    'phpdoc_line_span'                                 => ['const' => 'single', 'method' => 'single', 'property' => 'single'],
    'phpdoc_order'                                     => true,
    'phpdoc_to_comment'                                => ['ignored_tags' => ['noinspection', 'noRector']],
    'single_line_throw'                                => false,
    'single_line_comment_spacing'                      => false,
    'yoda_style'                                       => false,
  ])
  ->setFinder(
    PhpCsFixer\Finder::create()
      ->in(__DIR__ . DIRECTORY_SEPARATOR . 'src')
      ->files()->notName('Configuration.php')
  );
