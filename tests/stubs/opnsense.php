<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

/**
 * Stand-ins for the OPNsense classes this plugin is written against, so that the parts of
 * it that are ours can be exercised on a machine without OPNsense.
 *
 * Deliberately minimal: enough to load our classes and to call the methods under test, and
 * no more. A stub that grew into a simulation would start passing tests the real thing
 * would fail. Anything that genuinely needs core - account creation, group membership,
 * session handling - is not unit tested here; that is what the watchdog on the firewall is
 * for, and it fetches the real login page rather than a model of one.
 */

namespace OPNsense\Auth {
    interface IAuthConnector
    {
        public static function getType();
        public function setProperties($config);
        public function getLastAuthProperties();
        public function getLastAuthErrors();
        public function preauth($config);
        public function authenticate($username, $password);
    }

    class Base
    {
        public function getLastAuthErrors()
        {
            return [];
        }

        /**
         * Core reads the local accounts out of config.xml. Here they are whatever a test
         * put in the Directory, matched by name - case-insensitively, which is what core
         * does when caseInSensitiveUsernames is on, so that the spelling a caller gets
         * back can be checked at all.
         */
        protected function getUser($username)
        {
            foreach (Directory::$users as $user) {
                if (strcasecmp((string)$user->name, (string)$username) === 0) {
                    return $user;
                }
            }

            return null;
        }

        protected function setGroupMembership($username, $memberof, $scope = [], $create = false, $default = [])
        {
            /* recorded, never acted on - see the note at the top of this file */
            Recorder::$groupCalls[] = compact('username', 'memberof', 'scope', 'create', 'default');
        }
    }

    /** collects what a stub was asked to do, so a test can look at it */
    class Recorder
    {
        public static array $groupCalls = [];
        public static array $backendCalls = [];

        public static function reset(): void
        {
            self::$groupCalls = [];
            self::$backendCalls = [];
        }
    }

    /**
     * The local accounts of the machine a test is pretending to be.
     *
     * Deliberately flat objects rather than a config.xml: what the code under test does
     * with an account is read name, email, disabled, expires and uid off it, and casting
     * each to a string - which reads the same on one of these as on the SimpleXMLElement
     * core hands back.
     */
    class Directory
    {
        /** @var object[] */
        public static array $users = [];

        /** whether "auth add user" is to succeed */
        public static bool $creationWorks = true;

        public static function reset(): void
        {
            self::$users = [];
            self::$creationWorks = true;
        }

        public static function add(array $fields): void
        {
            self::$users[] = (object)($fields + ['uid' => (string)(1000 + count(self::$users))]);
        }
    }
}

namespace OPNsense\Core {
    /**
     * Just enough of the configuration for the parts that read local accounts out of it.
     * Everything else about core's Config - locking, saving, reloading - is nothing this
     * side is allowed to have an opinion about, so it is not modelled, only tolerated.
     */
    class Config
    {
        private static ?Config $instance = null;

        public static function getInstance(): Config
        {
            return self::$instance ??= new self();
        }

        public function object()
        {
            $config = new \stdClass();
            $config->system = new \stdClass();
            $config->system->user = \OPNsense\Auth\Directory::$users;

            return $config;
        }

        public function forceReload()
        {
        }
    }

    /** the configd client; records what it was asked and answers the way configd would */
    class Backend
    {
        public function configdpRun($event, $params = [])
        {
            \OPNsense\Auth\Recorder::$backendCalls[] = ['event' => $event, 'params' => $params];

            if ($event !== 'auth add user' || !\OPNsense\Auth\Directory::$creationWorks) {
                return json_encode(['status' => 'failed']);
            }

            \OPNsense\Auth\Directory::add(['name' => (string)($params[0] ?? '')]);

            return json_encode(['status' => 'ok']);
        }
    }
}

namespace OPNsense\Auth\SSOProviders {
    interface ISSOContainer
    {
        public function listProviders(): \Generator;
    }

    class Provider
    {
        public readonly string $id;
        public readonly string $appcode;
        public readonly string $name;
        public readonly string $login_uri;
        public readonly string $service;
        public readonly string $html_content;

        public function __construct(array $props)
        {
            foreach (get_class_vars(get_class($this)) as $key => $unused) {
                $this->$key = $props[$key] ?? '';
            }
        }
    }
}

namespace OPNsense\Mvc {
    class Request
    {
        public function __construct(
            private string $scheme = 'https',
            private string $host = 'firewall.example.net'
        ) {
        }

        public function getScheme(): string
        {
            return $this->scheme;
        }

        public function getHeader(string $name): string
        {
            return strtoupper($name) === 'HOST' ? $this->host : '';
        }

        public function get(string $name, $default = null)
        {
            return $default;
        }
    }

    class Response
    {
    }

    class Session
    {
    }

    class Controller
    {
    }
}

namespace {
    if (!function_exists('gettext')) {
        function gettext(string $text): string
        {
            return $text;
        }
    }

    if (!function_exists('config_read_array')) {
        function config_read_array(...$path): array
        {
            return [];
        }
    }
}
