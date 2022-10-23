<?php

function file_build_path(...$segments)
{
    return implode(DIRECTORY_SEPARATOR, $segments);
}

require_once file_build_path(getcwd(), 'vendor', 'autoload.php');

use App\components\Router;

$router = new Router();
$router->run();