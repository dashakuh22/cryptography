<?php

namespace App\components;

use DateTime;
use DateTimeInterface;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
use Stringable;

class Logger extends AbstractLogger implements LoggerInterface
{

    public string $template = "{date} {level} {message} {context}";

    private string $dateFormat = DateTimeInterface::RFC850;

    private mixed $configs;

    private string $fileDir;

    private string $name;

    public function __construct(string $name)
    {
        $this->configs = require file_build_path(getcwd(), 'config', 'configDirectories.php');
        $this->fileDir = file_build_path(getcwd(), $this->configs[$name]);
        date_default_timezone_set('Europe/Minsk');
        $this->name = $this->configs[$name];
        @mkdir($this->fileDir);
    }

    public function log($level, Stringable|string $message, array $context = []): void
    {
        file_put_contents(
            file_build_path($this->fileDir, $this->getLogName()),
            trim(strtr($this->template, [
                '{date}' => $this->getDate(),
                '{level}' => $level,
                '{message}' => $message,
                '{context}' => $this->contextStringify($context),
            ])) . PHP_EOL, FILE_APPEND);
    }

    public function getLogName(): string
    {
        return $this->name . '_' . date('dmY') . '.log';
    }

    public function getDate(): string
    {
        return (new DateTime())->format($this->dateFormat);
    }

    public function contextStringify(array $context = []): bool|string|null
    {
        return empty($context) ? null : json_encode($context);
    }

}