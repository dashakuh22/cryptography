<?php

namespace App\models;

use App\components\DB;
use PDO;

class UserModel
{

    const HASH_ALGO = PASSWORD_BCRYPT;

    public function getUserAttribute(string $attribute, string $email, string $password): mixed
    {
        $db = DB::getConnection();

        $query = 'SELECT ' . $attribute . ' , password FROM ' . DB::$dbName . ' WHERE email=:email';

        $result = $db->prepare($query);
        $result->bindParam(':email', $email);
        $result->execute();
        $userInfo = $result->fetch(PDO::FETCH_ASSOC);

        if ($userInfo) {
            if (password_verify($password, $userInfo['password'])) {
                return $userInfo[$attribute];
            }
        }

        return '';
    }

    public function getUserAttributeByID(string $attribute, string $id): mixed
    {
        $db = DB::getConnection();

        $query = 'SELECT ' . $attribute . ' FROM ' . DB::$dbName . ' WHERE id=:id';

        $result = $db->prepare($query);
        $result->bindParam(':id', $id);
        $result->execute();
        $userInfo = $result->fetch(PDO::FETCH_ASSOC);

        return $userInfo[$attribute];
    }

    public function getUserByID(string $id): array
    {
        $db = DB::getConnection();

        $query = 'SELECT * FROM ' . DB::$dbName . ' WHERE id=:id';

        $result = $db->prepare($query);
        $result->bindParam(':id', $id, PDO::PARAM_INT);
        $result->execute();

        $userInfo = $result->fetch(PDO::FETCH_ASSOC);

        $user = [
          'first_name' => $userInfo['first_name'],
          'last_name' => $userInfo['last_name'],
          'email' => $userInfo['email'],
          'age' => $userInfo['age'],
        ];

        return $user;
    }

    public function getUserByEmail(string $email): bool
    {
        $db = DB::getConnection();

        $query = 'SELECT id FROM ' . DB::$dbName . ' WHERE email=:email';

        $result = $db->prepare($query);
        $result->bindParam(':email', $email);
        $result->execute();

        return $result->rowCount() > 0;
    }

    public function addUser(string $email, string $firstName, string $lastName, string $password, string $secret): bool
    {
        $db = DB::getConnection();

        $query = 'INSERT IGNORE INTO ' . DB::$dbName . ' (email, first_name, last_name, password, secret) 
                  VALUES (:email, :first_name, :last_name, :password, :secret)';

        $result = $db->prepare($query);
        $result->bindParam(':email', $email);
        $result->bindParam(':first_name', $firstName);
        $result->bindParam(':last_name', $lastName);
        $passwordHash = self::getHash($password);
        $result->bindParam(':password', $passwordHash);;
        $result->bindParam(':secret', $secret);

        return $result->execute();
    }

    public function editUser(string $firstName, string $lastName, string $age, string $userId): bool
    {
        $db = DB::getConnection();

        $query = 'UPDATE ' . DB::$dbName . ' SET first_name=:first_name, last_name=:last_name, age=:age WHERE id=:id';

        $result = $db->prepare($query);
        $result->bindParam(':first_name', $firstName);
        $result->bindParam(':last_name', $lastName);
        $result->bindParam(':age', $age);
        $result->bindParam(':id', $userId, PDO::PARAM_INT);

        return $result->execute();
    }

    public function getHash(string $password): string
    {
        return password_hash($password, self::HASH_ALGO);
    }

}