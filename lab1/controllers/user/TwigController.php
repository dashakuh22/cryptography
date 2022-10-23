<?php

namespace App\controllers\user;

use RegistrationController;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

class TwigController
{

    public Environment $twig;
    public FilesystemLoader $loader;

    public function __construct()
    {
        $this->loader = new FilesystemLoader('views/user');
        $this->twig = new Environment($this->loader, [
            'cache' => false
        ]);
    }

    public function getAuthentication(): void
    {
        $checkValue = $this->getCheckValue();

        echo $this->twig->render('authentication.html.twig', [
            'check_value' => $checkValue,
        ]);
    }


    public function get2FA(string $qrCodeImage, int $userID): void
    {
        $checkValue = $this->getCheckValue();

        echo $this->twig->render('2fauthentication.html.twig', [
            'check_value' => $checkValue,
            'qr' => $qrCodeImage,
            'id' => $userID
        ]);
    }

    public function getRegistration(): void
    {
        $rand = $this->getCheckValue();

        echo $this->twig->render('registration.html.twig', [
            'check_value' => $rand,
            'password_info' => RegistrationController::PASSWORD_INFO
        ]);
    }

    public function getNotification(bool $isSuccess, array $errors): void
    {
        $checkValue = $this->getCheckValue();

        echo $this->twig->render('notification.html.twig', [
            'check_value' => $checkValue,
            'notification' => $errors,
            'action' => $isSuccess ? 'user-form' : '',
            'icon' => $isSuccess ? 'done' : 'close',
            'result' => $isSuccess ? 'success' : 'error',
        ]);
    }

    public function getRegistrationResult(bool   $isRegistered, array $errors, string $email,
                                          string $firstName, string $lastName): void
    {
        $rand = $this->getCheckValue();

        echo $this->twig->render('registration.html.twig', [
            'check_value' => $rand,
            'email' => $email,
            'first_name' => $firstName,
            'last_name' => $lastName,

            'showResult' => 'fade in',
            'notification' => $errors,
            'icon' => $isRegistered ? 'done' : 'close',
            'result' => $isRegistered ? 'success' : 'error',
            'password_info' => RegistrationController::PASSWORD_INFO,
        ]);
    }

    public function getUserForm(array $userInfo): void
    {
        $rand = $this->getCheckValue();

        echo $this->twig->render('index.html.twig', [
            'check_value' => $rand,
            'user' => $userInfo
        ]);
    }

    private function getCheckValue(): int
    {
        $rand = rand();
        $_SESSION['check_value'] = $rand;

        return $rand;
    }

}