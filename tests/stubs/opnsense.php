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
         * put in the Directory, matched exactly.  OPNsense ships with
         * caseInSensitiveUsernames disabled, and identity bootstrap must not quietly
         * turn two differently cased local accounts into the same account.
         */
        protected function getUser($username)
        {
            foreach (Directory::$users as $user) {
                if ((string)$user->name === (string)$username) {
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

    class AuthenticationFactory
    {
        public function get(string $name)
        {
            foreach (\OPNsense\Core\Config::getInstance()->object()->system->authserver ?? [] as $server) {
                if ((string)($server->name ?? '') !== $name) {
                    continue;
                }
                $connector = new OpenIDConnect();
                $connector->setProperties((array)$server);
                return $connector;
            }
            throw new \RuntimeException('Authentication server not found');
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

        /** optional configd output, including malformed output from real core versions */
        public static ?string $creationOutput = null;

        public static function reset(): void
        {
            self::$users = [];
            self::$creationWorks = true;
            self::$creationOutput = null;
            \OPNsense\Core\Config::reset();
        }

        public static function add(array $fields): void
        {
            self::$users[] = (object)($fields + ['uid' => (string)(1000 + count(self::$users))]);
        }
    }
}

namespace OPNsense\Core {
    class SanitizeFilter
    {
        public function sanitize($value, $type)
        {
            $value = (string)$value;
            return $type === 'local_uri' && str_starts_with($value, '/')
                && !str_starts_with($value, '//') ? $value : '';
        }
    }

    /**
     * Just enough of the configuration for subject bindings to exercise the same
     * lock/change/save cycle used on OPNsense.
     */
    class Config
    {
        private static ?Config $instance = null;
        private object $root;
        public int $saves = 0;

        private function __construct()
        {
            $this->root = (object)['system' => (object)[
                'user' => [],
                'authserver' => [],
            ]];
        }

        public static function getInstance(): Config
        {
            return self::$instance ??= new self();
        }

        public function object()
        {
            $this->root->system->user = \OPNsense\Auth\Directory::$users;
            return $this->root;
        }

        public static function reset(): void
        {
            self::$instance = null;
        }

        public function addAuthServer(array $settings): object
        {
            $server = (object)($settings + ['type' => 'openidconnect', 'openidconnect_app_code' => 'main']);
            $this->root->system->authserver[] = $server;
            return $server;
        }

        public function lock(): void
        {
        }

        public function unlock(): void
        {
        }

        public function save(): void
        {
            $this->saves++;
        }

        public function forceReload(): void
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

            return \OPNsense\Auth\Directory::$creationOutput ?? json_encode(['status' => 'ok']);
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
        private array $query;
        private array $post;
        private array $headers;

        public function __construct(
            private string $scheme = 'https',
            private string $host = 'firewall.example.net',
            array $query = [],
            array $post = [],
            array $headers = [],
            private string $rawBody = '',
            private string $method = 'GET'
        ) {
            $this->query = $query;
            $this->post = $post;
            $this->headers = array_change_key_case($headers, CASE_UPPER);
        }

        public function getScheme(): string
        {
            return $this->scheme;
        }

        public function getHeader(string $name): string
        {
            return strtoupper($name) === 'HOST'
                ? $this->host : (string)($this->headers[strtoupper($name)] ?? '');
        }

        public function get(string $name, $default = null)
        {
            return $this->query[$name] ?? $default;
        }

        public function getPost(string $name, $filters = null, $default = null)
        {
            return $this->post[$name] ?? $default;
        }

        public function getRawBody(): string
        {
            return $this->rawBody;
        }

        public function isPost(): bool
        {
            return strtoupper($this->method) === 'POST';
        }
    }

    class Response
    {
        public ?string $redirectedTo = null;
        public array $headers = [];
        public ?array $status = null;

        public function redirect(string $target): self
        {
            $this->redirectedTo = $target;
            return $this;
        }

        public function setContentType(string $type, string $charset = ''): self
        {
            $this->headers['Content-Type'] = $type . ($charset === '' ? '' : '; charset=' . $charset);
            return $this;
        }

        public function setHeader(string $name, string $value): self
        {
            $this->headers[$name] = $value;
            return $this;
        }

        public function setStatusCode(int $code, string $status): self
        {
            $this->status = [$code, $status];
            return $this;
        }
    }

    class Session
    {
        private array $values = [];

        public function get(string $name, $default = null)
        {
            return $this->values[$name] ?? $default;
        }

        public function set(string $name, $value): void
        {
            $this->values[$name] = $value;
        }

        public function remove(string $name): void
        {
            unset($this->values[$name]);
        }
    }

    class Controller
    {
        public Session $session;
        public Request $request;
        public Response $response;

        public function __construct(?Request $request = null, ?Session $session = null)
        {
            $this->request = $request ?? new Request();
            $this->session = $session ?? new Session();
            $this->response = new Response();
        }
    }
}

namespace OPNsense\Base {
    class ApiControllerBase extends \OPNsense\Mvc\Controller
    {
        public function beforeExecuteRoute($dispatcher)
        {
            return true;
        }

        protected function isExternalClient(): bool
        {
            return false;
        }
    }
}

namespace {
    class OidcTestNetwork
    {
        public static array $addresses = [
            '192.0.2.1' => 'lan',
            '2001:db8::1' => 'lan',
            '127.0.0.1' => 'lo0',
            'fe80::1%lan' => 'lan',
        ];
        public static array $virtualIps = [];
    }

    if (!function_exists('gettext')) {
        function gettext(string $text): string
        {
            return $text;
        }
    }

    if (!function_exists('config_read_array')) {
        function config_read_array(...$path): array
        {
            if (array_slice($path, 0, 2) === ['virtualip', 'vip']) {
                return OidcTestNetwork::$virtualIps;
            }
            return [];
        }
    }

    if (!function_exists('get_configured_ip_addresses')) {
        function get_configured_ip_addresses(): array
        {
            return OidcTestNetwork::$addresses;
        }
    }

}
