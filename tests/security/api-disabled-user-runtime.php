<?php
declare(strict_types=1);

/**
 * Executes the real modules/App/api.php route handler with an isolated fake
 * data store. This is a focused runtime regression probe, not an HTTP test.
 */
final class FakeAuth {
    public array $user = [];
    public function setUser(array $user, bool $permanent = true): void { $this->user = $user; }
}
final class FakeRspc { public function handle($request, $context): bool { return false; } }
final class FakeStore {
    public function findOne(string $collection, array $filter): array|false {
        if ($collection !== 'system/users' || $filter !== ['apiKey' => 'USR-disabled-test-key']) return false;
        return ['_id' => 'disabled-user-id', 'user' => 'disabled-user', 'role' => 'admin', 'active' => false];
    }
}
final class FakeGql {
    public function process($query, $variables) { return ['authenticated_as' => $GLOBALS['harness']->auth->user]; }
}
final class FakeRequest { public array $server = ['HTTP_API_KEY' => 'USR-disabled-test-key']; public string $method = 'GET'; }
final class FakeResponse { public int $status = 200; public string $body = ''; }
final class ApiHarness {
    public FakeRequest $request;
    public FakeResponse $response;
    public FakeStore $dataStorage;
    public FakeAuth $auth;
    public FakeGql $gql;
    public $handler;
    public function __construct() {
        $this->request = new FakeRequest(); $this->response = new FakeResponse();
        $this->dataStorage = new FakeStore(); $this->auth = new FakeAuth(); $this->gql = new FakeGql();
    }
    public function service($name, $factory): void {}
    public function bind($route, $handler): void { $this->handler = $handler; }
    public function param($name, $default = null) { return $default; }
    public function helper($name) { return $name === 'auth' ? $this->auth : new FakeRspc(); }
    public function __get($name) { return null; }
    public function loadRoute(): void { include dirname(__DIR__, 2).'/modules/App/api.php'; }
}
$GLOBALS['harness'] = new ApiHarness();
$GLOBALS['harness']->loadRoute();
$result = ($GLOBALS['harness']->handler)([':splat' => ['gql']]);
$user = $GLOBALS['harness']->auth->user;
if (($user['user'] ?? null) !== 'disabled-user' || ($user['_id'] ?? null) !== 'disabled-user-id') {
    fwrite(STDERR, "API-key probe did not authenticate the seeded fixture; result=".json_encode($result)."\n");
    exit(1);
}
echo "CONFIRMED: real API route handler accepts an API key belonging to active=false user; auth context user=".$user['user']."\n";
