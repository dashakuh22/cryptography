<?php

namespace App\controllers;

class DataController
{

    public static function makeDataSecure(array $data): array
    {
        foreach ($data as $field => $value) {
            $data[$field] = self::getSecure($value);
        }

        return $data;
    }

    public static function getSecure(string $data): string
    {
        return htmlspecialchars(stripslashes(trim($data)));
    }

}
