<?php

use App\models\UserModel;
use App\controllers\user\TwigController;
use RobThree\Auth\TwoFactorAuth;

class RegistrationController
{

    public array $error;

    public array $errors = [
        'success' => 'You have successfully registered! Enter the following secret code to the Authenticator App under your email: ',
        'bad user' => 'This email has already used.',
        'bad email' => 'Check your email for correctness.',
        'bad first name' => 'Check your first name for correctness.',
        'bad last name' => 'Check your last name for correctness.',
        'bad password' => 'Check your password for correctness.',
        'bad connection' => 'Check yor database params before using this app.',
        'wrong email' => 'The email confirmation does\'t match.',
        'wrong password' => 'The password confirmation does\'t match.',
    ];

    public const PASSWORD_INFO = "Your password should have at least:<ul>
                       <li>1 digit</li>
                       <li>1 small character</li>
                       <li>1 capital character</li>
                       <li>1 special character</li>
                       <li>>= 6 characters long</li></ul>";

    public TwoFactorAuth $twoFactorAuth;
    public TwigController $twig;
    public UserModel $model;

    public function __construct()
    {
        $this->error = [];
        $this->twoFactorAuth = new TwoFactorAuth();
        $this->twig = new TwigController();
        $this->model = new UserModel();
    }

    public function actionIndex(): void
    {
        if (!isset($_COOKIE['userID'])) {
            $this->twig->getRegistration();
            exit();
        }
        header('Location: /file-form');
    }

    public function actionFail(): void
    {
        $this->error[] = $this->errors['bad connection'];
        $this->twig->getNotification(false, $this->error);
        exit();
    }

    public function actionRegister(): void
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {

            if (isset($_SESSION['check_value']) && $_POST['check_value'] == $_SESSION['check_value']) {

                $_POST = $this->makeDataSecure($_POST);

                $_SESSION['email'] = $_POST['email'];
                $_SESSION['first_name'] = $_POST['first_name'];
                $_SESSION['last_name'] = $_POST['last_name'];

                if ($this->registration()) {
                    $this->twig->getNotification(true, $this->error);
                } else {
                    $this->twig->getRegistrationResult(
                        false,
                        $this->error,
                        $_SESSION['email'],
                        $_SESSION['first_name'],
                        $_SESSION['last_name']
                    );
                }

                exit();

            } else {
                header('Location: /');
            }

        }
    }

    public function makeDataSecure(array $data): array
    {
        foreach ($data as $field => $value) {
            $data[$field] = $this->getSecure($value);
        }

        return $data;
    }

    public function getSecure(string $data): string
    {
        return htmlspecialchars(stripslashes(trim($data)));
    }

    public function registration(): bool
    {

        $this->checkEmail($_POST['email'], $_POST['confirm_email']);
        $this->checkFirstName($_POST['first_name']);
        $this->checkLastName($_POST['last_name']);
        $this->checkPassword($_POST['password'], $_POST['confirm_password']);

        if (empty($this->error)) {
            $secret = $this->twoFactorAuth->createSecret();
            $this->model->addUser(
                $_POST['email'],
                $_POST['first_name'],
                $_POST['last_name'],
                $_POST['password'],
                $secret
            );
            $_SESSION['email'] = '';
            $_SESSION['first_name'] = '';
            $_SESSION['last_name'] = '';
            $this->error[] = $this->errors['success'] . $secret;

            return true;
        }

        return false;
    }

    public function checkEmail(string $email, string $confirmEmail): void
    {
        if (!$this->checkEmailValidation($email)) {
            $this->error[] = $this->errors['bad email'];
            $_SESSION['email'] = '';

            return;
        }

        if ($this->model->getUserByEmail($email)) {
            $this->error[] = $this->errors['bad user'];
            $_SESSION['email'] = '';

            return;
        }

        if ($email !== $confirmEmail) {
            $this->error[] = $this->errors['wrong email'];
            $_SESSION['email'] = '';
        }
    }

    public function checkEmailValidation(string $email): string
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    public function checkFirstName(string $firstName): void
    {
        if (!$this->checkNameValidation($firstName)) {
            $this->error[] = $this->errors['bad first name'];
            $_SESSION['first_name'] = '';
        }
    }

    public function checkLastName(string $lastName): void
    {
        if (!$this->checkNameValidation($lastName)) {
            $this->error[] = $this->errors['bad last name'];
            $_SESSION['last_name'] = '';
        }
    }

    public function checkNameValidation(string $name): string
    {
        return preg_match('@^[A-z]*$@', $name);
    }

    public function checkPassword(string $password, string $confirmPassword): void
    {
        if (!$this->checkPasswordValidation($password)) {
            $this->error[] = $this->errors['bad password'];
            return;
        }

        if ($password !== $confirmPassword) {
            $this->error[] = $this->errors['wrong password'];
            $_SESSION['password'] = '';
        }
    }

    public function checkPasswordValidation(string $password): bool
    {
        return preg_match('@\d@', $password)
            && preg_match('@\W@', $password)
            && preg_match('@[A-ZА-Я]@', $password)
            && preg_match('@[a-zа-я]@', $password)
            && !preg_match('@\s@', $password)
            && strlen($password) >= 6;
    }

}