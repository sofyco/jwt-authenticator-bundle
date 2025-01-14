<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\Tests\Security\Guard;

use Sofyco\Bundle\JwtAuthenticatorBundle\Security\Encoder\JwtEncoder;
use Sofyco\Bundle\JwtAuthenticatorBundle\Security\Guard\TokenAuthenticator;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class TokenAuthenticatorTest extends WebTestCase
{
    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = self::createClient();
    }

    public function testSuccessAuthenticate(): void
    {
        $encoder = $this->getJwtEncoder();
        $response = $this->sendRequest($this->createAuthorizationHeader($encoder->encode('khaperets')));

        self::assertSame('{"user":"khaperets"}', $response->getContent());
        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
    }

    public function testTokenAbsent(): void
    {
        $response = $this->sendRequest($this->createAuthorizationHeader());

        self::assertSame('{"message":"security.auth.jwt.token.absent"}', $response->getContent());
        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    public function testTokenInvalid(): void
    {
        $response = $this->sendRequest($this->createAuthorizationHeader('foo'));

        self::assertSame('{"message":"security.auth.jwt.token.invalid"}', $response->getContent());
        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    public function testBadCredentials(): void
    {
        $encoder = $this->getJwtEncoder();
        $response = $this->sendRequest($this->createAuthorizationHeader($encoder->encode('baz')));

        self::assertSame(\json_encode(['message' => TokenAuthenticator::BAD_CREDENTIALS_MESSAGE]), $response->getContent());
        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    public function testExpiredToken(): void
    {
        $encoder = $this->getJwtEncoder();
        $response = $this->sendRequest($this->createAuthorizationHeader($encoder->encode('expired')));

        self::assertSame(\json_encode(['message' => 'security.session.inactive']), $response->getContent());
        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    public function testInvalidPrivateKey(): void
    {
        $tokenWIthInvalidPrivateKey = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3MzY4NjA0MDAuNTkyMjk3LCJleHAiOjMzMjkzNzY5MjAwLjU5MjMsImlkIjoia2hhcGVyZXRzIn0.XAjuI9pStKrS22rWojGfnx5hkGfKV0esKKeigrd5pZc';
        $response = $this->sendRequest($this->createAuthorizationHeader($tokenWIthInvalidPrivateKey));

        self::assertSame(\json_encode(['message' => 'security.auth.jwt.token.invalid']), $response->getContent());
        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    private function sendRequest(array $headers = []): Response
    {
        $this->client->request(method: Request::METHOD_GET, uri: '/', server: $headers);

        return $this->client->getResponse();
    }

    private function getJwtEncoder(): JwtEncoder
    {
        return $this->client->getContainer()->get(JwtEncoder::class); //@phpstan-ignore-line
    }

    private function createAuthorizationHeader(string $value = ''): array
    {
        return ['HTTP_' . TokenAuthenticator::HEADER_NAME => TokenAuthenticator::HEADER_VALUE_PREFIX . $value];
    }
}
