<?php

use App\models\UserModel;
use App\controllers\user\TwigController;
use App\controllers\DataController;

class UserController
{

    public array $error;

    public array $errors = [
        'success' => "Welcome back, ",
        'bad connection' => 'Check yor database params before using this app.',
    ];

    public TwigController $twig;
    public UserModel $model;

    public function __construct()
    {
        $this->error = [];
        $this->model = new UserModel();
        $this->twig = new TwigController();
    }

    public function actionIndex(): void
    {
        if (isset($_COOKIE['userID'])) {

            if (isset($_SESSION['check_value']) && isset($_POST['check_value'])
                && $_POST['check_value'] == $_SESSION['check_value']) {

                $data = DataController::makeDataSecure($_POST);
                $this->model->editUser($data['first_name'], $data['last_name'], $data['age'], $_COOKIE['userID']);
            }

            $user = $this->model->getUserByID($_COOKIE['userID']);

            $this->twig->getUserForm($user);
            exit();

        } else {
            header('Location: /');
        }
    }

}