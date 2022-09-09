<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\Message;

final class AuthenticationSuccess
{
    public function __construct(public readonly string $userIdentifier, public readonly string $token, public readonly string $ip)
    {
    }
}
