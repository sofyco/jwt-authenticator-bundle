<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\Security\Guard;

use Sofyco\Bundle\JwtAuthenticatorBundle\Message\AuthenticationSuccess;
use Sofyco\Bundle\JwtAuthenticatorBundle\Security\Encoder\JwtEncoder;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
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
    public const string BAD_CREDENTIALS_MESSAGE = 'security.auth.jwt.badCredentials';
    public const string HEADER_NAME = 'Authorization';
    public const string HEADER_VALUE_PREFIX = 'Bearer ';

    public function __construct(private readonly JwtEncoder $encoder, private readonly MessageBusInterface $messageBus)
    {
    }

    public function supports(Request $request): ?bool
    {
        $header = $request->headers->get(self::HEADER_NAME);

        return null !== $header && \str_starts_with($header, self::HEADER_VALUE_PREFIX);
    }

    public function authenticate(Request $request): Passport
    {
        $token = \str_replace(self::HEADER_VALUE_PREFIX, '', (string) $request->headers->get(self::HEADER_NAME));

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
                token: $token,
                ip: (string) $request->getClientIp(),
            ));
        } catch (HandlerFailedException $exception) {
            $exception = \current($exception->getWrappedExceptions());

            if ($exception instanceof ServiceUnavailableHttpException) {
                throw $exception;
            } elseif (false !== $exception) {
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
}
