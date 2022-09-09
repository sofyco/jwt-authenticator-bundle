<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\Security\Guard;

use Sofyco\Bundle\JwtAuthenticatorBundle\Message\AuthenticationSuccess;
use Sofyco\Bundle\JwtAuthenticatorBundle\Security\Encoder\JwtEncoder;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\Exception\HandlerFailedException;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class TokenAuthenticator extends AbstractAuthenticator
{
    public const BAD_CREDENTIALS_MESSAGE = 'security.auth.jwt.badCredentials';
    public const HEADER_NAME = 'Authorization';
    public const HEADER_VALUE_PREFIX = 'Bearer ';

    public function __construct(private readonly JwtEncoder $encoder, private readonly MessageBusInterface $messageBus)
    {
    }

    public function supports(Request $request): ?bool
    {
        return null !== $this->getAuthorizationToken($request);
    }

    public function authenticate(Request $request): Passport
    {
        $token = $this->getAuthorizationToken($request);

        if (empty($token)) {
            throw new Exception\TokenAbsentException();
        }

        try {
            $userIdentifier = $this->encoder->decode($token);
        } catch (\Throwable $throwable) {
            throw new Exception\InvalidTokenException();
        }

        try {
            $this->messageBus->dispatch(new AuthenticationSuccess(
                userIdentifier: $userIdentifier,
                token: (string) $this->getAuthorizationToken($request),
                ip: (string) $request->getClientIp(),
            ));
        } catch (HandlerFailedException $exception) {
            if (false !== $exception = \current($exception->getNestedExceptions())) {
                throw new CustomUserMessageAuthenticationException($exception->getMessage());
            }
        }

        return new SelfValidatingPassport(new UserBadge($userIdentifier));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $message = $exception->getMessage();

        if ($exception instanceof BadCredentialsException) {
            $message = self::BAD_CREDENTIALS_MESSAGE;
        }

        return new JsonResponse(['message' => $message], Response::HTTP_UNAUTHORIZED);
    }

    private function getAuthorizationToken(Request $request): ?string
    {
        $header = $request->headers->get(self::HEADER_NAME);

        if (null === $header || false === \str_starts_with($header, self::HEADER_VALUE_PREFIX)) {
            return null;
        }

        return \str_replace(self::HEADER_VALUE_PREFIX, '', $header);
    }
}
