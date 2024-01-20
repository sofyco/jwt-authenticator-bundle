<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\Security\Guard\Exception;

use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

final class InvalidTokenException extends CustomUserMessageAuthenticationException
{
    public const string MESSAGE = 'security.auth.jwt.token.invalid';

    public function __construct()
    {
        parent::__construct(self::MESSAGE);
    }
}
