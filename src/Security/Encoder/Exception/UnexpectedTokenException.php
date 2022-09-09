<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\Security\Encoder\Exception;

use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

final class UnexpectedTokenException extends CustomUserMessageAuthenticationException
{
    public const MESSAGE = 'security.auth.jwt.token.unexpected';

    public function __construct()
    {
        parent::__construct(self::MESSAGE);
    }
}
