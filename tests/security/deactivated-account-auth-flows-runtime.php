<?php
declare(strict_types=1);

/**
 * Executes the real Auth::validate2FA() and Identi::callback() methods with
 * isolated in-memory fixtures. No external IdP, database, or production account.
 */
namespace Lime {
    if (!function_exists(__NAMESPACE__.'\\fetch_from_array')) {
        function fetch_from_array($array, $path, $default = null) {
            foreach (explode('.', (string)$path) as $part) {
                if (!is_array($array) || !array_key_exists($part, $array)) return $default;
                $array = $array[$part];
            }
            return $array;
        }
    }
}
namespace {
    require dirname(__DIR__, 2).'/lib/vendor/autoload.php';
    require dirname(__DIR__, 2).'/modules/App/Controller/Auth.php';
    require dirname(__DIR__, 2).'/modules/Identi/Controller/Identi.php';

    final class ProbeRequest {
        public function __construct(private array $params = []) {}
        public function param($key, $default = null) { return $this->params[$key] ?? $default; }
    }
    final class ProbeSession {
        public array $writes = [];
        public function read($key, $default = null) {
            return $key === 'identi_oidc_provider' ? ($GLOBALS['probe_oidc'] ?? $default) : $default;
        }
        public function write($key, $value): void { $this->writes[$key] = $value; }
        public function delete($key): void {}
    }
    final class ProbeAuth {
        public array $user = [];
        public function setUser($user, ...$args): void { $this->user = (array)$user; }
    }
    final class ProbeJwt {
        public function decode($token) { return ['_id' => 'inactive-user-id']; }
    }
    final class ProbeTwoFa {
        public function verifyCode($secret, $code): bool { return $secret === 'fixture-secret' && $code === '123456'; }
    }
    final class ProbeCsrf {
        public function token($scope) { return 'fixture-csrf'; }
    }
    final class ProbeAcl {
        public function roles() { return [['appid' => 'admin']]; }
    }
    final class ProbeStore {
        public array $saved = [];
        public function findOne($collection, $filter) {
            if ($collection !== 'system/users') return false;
            if (($filter['_id'] ?? null) === 'inactive-user-id' || ($filter['_identi.sub'] ?? null) === 'oidc-subject-1') {
                return [
                    '_id' => 'inactive-user-id', 'user' => 'disabled-user',
                    'name' => 'Disabled User', 'email' => 'disabled@example.test',
                    'role' => 'admin', 'active' => false,
                    'twofa' => ['secret' => 'fixture-secret', 'enabled' => true],
                    '_identi' => ['sub' => 'oidc-subject-1'], 'password' => 'hash'
                ];
            }
            return false;
        }
        public function save($collection, $user): void { $this->saved[] = $user; }
    }
    final class ProbeOidc {
        public function authenticate(): void {}
        public function requestUserInfo() {
            return (object)['sub'=>'oidc-subject-1','preferred_username'=>'disabled-user','email'=>'disabled@example.test','name'=>'Disabled User'];
        }
        public function getIdToken() { return null; }
        public function getAccessToken() { return 'fixture-access-token'; }
    }
    final class ProbeApp {
        public ProbeRequest $request;
        public ProbeSession $session;
        public ProbeAuth $auth;
        public ProbeStore $dataStorage;
        public array $events = [];
        public function __construct(array $params = []) {
            $this->request = new ProbeRequest($params);
            $this->session = new ProbeSession();
            $this->auth = new ProbeAuth();
            $this->dataStorage = new ProbeStore();
        }
        public function helper($name) {
            return match($name) {
                'jwt' => new ProbeJwt(), 'twfa' => new ProbeTwoFa(),
                'auth' => $this->auth, 'session' => $this->session,
                'csrf' => new ProbeCsrf(), 'acl' => new ProbeAcl(),
                default => throw new RuntimeException('Unexpected helper '.$name)
            };
        }
        public function trigger($name, $args = []): void { $this->events[] = $name; }
        public function reroute($url): void {}
        public function hash($value) { return 'fixture-hash'; }
    }
    function attachApp(object $controller, ProbeApp $app): void {
        $r = new ReflectionObject($controller);
        while (!$r->hasProperty('app') && $r = $r->getParentClass()) {}
        $p = $r->getProperty('app');
        $p->setAccessible(true);
        $p->setValue($controller, $app);
    }

    // Test 1: a challenge is issued while active; account is now inactive.
    $authController = (new ReflectionClass(\App\Controller\Auth::class))->newInstanceWithoutConstructor();
    $authApp = new ProbeApp(['code'=>'123456', 'token'=>'previously-issued-2fa-challenge']);
    attachApp($authController, $authApp);
    $twofaResult = $authController->validate2FA();
    if (($twofaResult['success'] ?? false) !== true ||
        ($authApp->auth->user['user'] ?? null) !== 'disabled-user' ||
        !isset($authApp->session->writes['app.session.start'])) {
        fwrite(STDERR, "2FA runtime probe did not reproduce session creation for inactive account: ".json_encode($twofaResult)."\n");
        exit(1);
    }
    echo "CONFIRMED: real Auth::validate2FA() creates an authenticated session for active=false user when a previously issued challenge is valid.\n";

    // Test 2: valid OIDC callback resolves an existing inactive account.
    $GLOBALS['probe_oidc'] = new ProbeOidc();
    $identi = (new ReflectionClass(\Identi\Controller\Identi::class))->newInstanceWithoutConstructor();
    $oidcApp = new ProbeApp();
    attachApp($identi, $oidcApp);
    $config = [
        'mapping' => ['user'=>'preferred_username','email'=>'email','role'=>'role','name'=>'name'],
        'default_role' => 'admin',
        'allowed_roles' => ['admin']
    ];
    $cp = new ReflectionProperty(\Identi\Controller\Identi::class, 'config');
    $cp->setAccessible(true);
    $cp->setValue($identi, $config);
    $oidcResult = $identi->callback();
    if (($oidcApp->auth->user['user'] ?? null) !== 'disabled-user' ||
        ($oidcApp->auth->user['active'] ?? null) !== false ||
        !isset($oidcApp->session->writes['app.session.start'])) {
        fwrite(STDERR, "OIDC runtime probe did not reproduce session creation for inactive account: ".json_encode($oidcResult)."\n");
        exit(1);
    }
    echo "CONFIRMED: real Identi::callback() creates an authenticated session for an existing active=false account returned by the OIDC provider.\n";
}
