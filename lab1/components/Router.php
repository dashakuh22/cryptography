<?php

namespace App\components;

class Router
{

    private mixed $routes;

    public function __construct()
    {
        session_start();
        $this->routes = include file_build_path(getcwd(), 'config', 'configRoutes.php');
    }

    public function getURI(): ?string
    {
        if (!empty($_SERVER['REQUEST_URI'])) {
            return trim($_SERVER['REQUEST_URI'], '/');
        }
        return null;
    }

    public function run(): void
    {
        $uri = $this->getURI();

        foreach ($this->routes as $uriPattern => $path) {
            if (preg_match("~$uriPattern~", $uri)) {

                $internalRoute = preg_replace("~$uriPattern~", $path, $uri);
                $pathParts = explode('/', $internalRoute);

                $controller = array_shift($pathParts);
                $controllerName = ucfirst(array_shift($pathParts) . 'Controller');
                $actionName = 'action' . ucfirst(array_shift($pathParts));
                $params = $pathParts;

                $controllerFile = file_build_path(getcwd(), 'controllers', $controller, $controllerName . '.php');

                if (file_exists($controllerFile)) {
                    require_once $controllerFile;
                }

                $controllerObject = new $controllerName;
                $result = call_user_func_array(array($controllerObject, $actionName), $params);
                if (!is_null($result)) {
                    break;
                }
            }
        }

    }

}