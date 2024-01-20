<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\Security\Encoder\Exception;

use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

final class UnexpectedIdentifierException extends CustomUserMessageAuthenticationException
{
    public const string MESSAGE = 'security.auth.jwt.identifier.unexpected';

    public function __construct()
    {
        parent::__construct(self::MESSAGE);
    }
}
