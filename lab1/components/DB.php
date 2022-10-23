<?php

namespace App\components;

use Exception;
use PDO;

class DB
{

    public static string $dbName;

    public static function getConnection(): PDO
    {
        try {

            $paramsPath = file_build_path(getcwd(), 'config', 'configDB.php');
            $params = include $paramsPath;

            self::$dbName = $params['dbTableName'];
            $dsn = "mysql:host={$params['host']};dbname={$params['dbName']}";

            return new PDO($dsn, $params['userName'], $params['password']);

        } catch (Exception $e) {
            header('Location: /fail');
            die();
        }
    }
}