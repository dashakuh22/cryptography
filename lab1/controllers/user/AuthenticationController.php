<?php

use App\components\Logger;
use App\models\UserModel;
use App\controllers\user\TwigController;
use App\controllers\DataController;
use RobThree\Auth\TwoFactorAuth;

class AuthenticationController
{

    public const ATTEMPTS_COUNT = 3;

    public const BLOCK_TIME = 5 * 60;
    public const COOKIE_WEEK = 7 * 24 * 60 * 60;
    public const COOKIE_MINUTE = 60;

    public array $error;

    public array $errors = [
        'success' => "Welcome back, ",
        'bad login' => 'Login is incorrect.',
        'bad 2fa' => '2FA is incorrect.',
        'bad attempts' => 'Only 3 attempts are allowed. Please, wait for 5 minutes.',
        'bad connection' => 'Check yor database params before using this app.',
    ];

    public TwoFactorAuth $twoFactorAuth;
    public TwigController $twig;
    public UserModel $model;
    public Logger $logger;

    public function __construct()
    {
        $this->error = [];
        $this->twoFactorAuth = new TwoFactorAuth();
        $this->logger = new Logger('attacks_log');
        $this->model = new UserModel();
        $this->twig = new TwigController();
    }

    public function actionIndex(): void
    {
        if (!isset($_COOKIE['userID'])) {
            $this->twig->getAuthentication();
            exit();
        } else {
            header('Location: /user-form');
        }
    }

    public function actionFail(): void
    {
        $this->error[] = $this->errors['bad connection'];
        $this->twig->getNotification(false, $this->error);
        exit();
    }

    public function action2FA(): void
    {
        $userID = $_POST['id'];
        $userSecret = $this->model->getUserAttributeByID('secret', $userID);

        if ($this->twoFactorAuth->verifyCode($userSecret,  $_POST['qr'])) {
            unset($_SESSION['attempts']);

            if (isset($_SESSION['remember'])) {
                setcookie('userID', $userID, time() + self::COOKIE_WEEK);
            } else {
                setcookie('userID', $userID, time() + self::COOKIE_MINUTE);
            }

            $this->error[] = $this->errors['success'] . $this->model->getUserAttributeByID('first_name', $userID);
            $this->twig->getNotification(true, $this->error);

        } else {
            $this->error[] = $this->errors['bad 2fa'];
            $this->twig->getNotification(false, $this->error);
        }

        exit();
    }

    public function actionLogout(): void
    {
        if (isset($_COOKIE['userID'])) {
            setcookie('userID', '', time() - self::COOKIE_WEEK);
        }
        header('Location: /');
    }

    public function actionLogin(): void
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {

            if (!$this->isAttemptAvailable()) {
                $this->twig->getNotification(false, $this->error);
                exit();
            }

            if (isset($_SESSION['check_value']) && $_SESSION['check_value'] == $_POST['check_value']) {

                $data = DataController::makeDataSecure($_POST);

                $_SESSION['email'] = $data['email'];
                $_SESSION['password'] = $data['password'];
                $_SESSION['remember'] = $data['remember'];

                $userID = $this->model->getUserAttribute('id', $data['email'], $data['password']);

                if (!empty($userID)) {

                    $qrCodeImage = $this->twoFactorAuth->getQRCodeImageAsDataUri(
                        $data['email'],
                        $this->model->getUserAttribute('secret', $data['email'], $data['password'])
                    );

                    $this->twig->get2FA($qrCodeImage, $userID);
                } else {
                    $this->error[] = $this->errors['bad login'];
                    $this->twig->getNotification(false, $this->error);
                }
                exit();

            } else {
                header('Location: /');
            }

        }
    }

    public function isAttemptAvailable(): bool
    {
        $userIP = $this->getIP();

        if (!isset($_SESSION['attempts'][$userIP])) {
            $_SESSION['attempts'][$userIP] = 1;
            $_SESSION['block'][$userIP] = false;
            $_SESSION['last_attempt_time'][$userIP] = time();
        }

        if ($this->isTooManyAttempts($userIP)) {

            if ($this->isIpBlocked($userIP)) {
                $this->error[] = $this->errors['bad attempts'];
                $this->error[] = 'Left time: ' . $this->getLeftMinutes($userIP) . ' minutes';

                if (!$_SESSION['block'][$userIP]) {
                    $this->logger->notice('Attack', [
                        'ip' => $userIP,
                        'email' => $_POST['email'],
                        'start' => date('d-m-Y H:i:s', $this->getLastTimeAttempt($userIP)),
                        'end' => date('d-m-Y H:i:s', $this->getEndOfBlock($userIP))
                    ]);
                }

                $_SESSION['block'][$userIP] = true;

            } else {
                unset($_SESSION['attempts'][$userIP]);

                return true;
            }

            return false;
        }

        $_SESSION['attempts'][$userIP]++;
        $_SESSION['last_attempt_time'][$userIP] = time();

        return true;
    }

    public function isTooManyAttempts(string $ip): bool
    {
        return $_SESSION['attempts'][$ip] >= self::ATTEMPTS_COUNT;
    }

    public function isIpBlocked(string $ip): bool
    {
        return time() < $this->getEndOfBlock($ip);
    }

    public function getLastTimeAttempt(string $ip): int
    {
        return $_SESSION['last_attempt_time'][$ip];
    }

    public function getEndOfBlock(string $ip): int
    {
        return $_SESSION['last_attempt_time'][$ip] + self::BLOCK_TIME;
    }

    public function getLeftMinutes(string $ip): int
    {
        return $this->getMinutes($this->getEndOfBlock($ip) - time());
    }

    public function getMinutes(int $time): int
    {
        return ceil($time / 60);
    }

    public function getIP(): string
    {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }

        return $_SERVER['REMOTE_ADDR'];
    }

}