<?php

// A synthetic release for the refresh service's filesystem/failure tests.
if (($argv[1] ?? null) !== 'config:cache') {
    exit(2);
}
if (getenv('FAIL_CONFIG_REFRESH') === '1') {
    exit(23);
}
$path = getenv('APP_CONFIG_CACHE');
if (! $path || is_file($path)) {
    exit(3);
}
file_put_contents($path, "<?php return ['fixture' => 'refreshed'];\n");
