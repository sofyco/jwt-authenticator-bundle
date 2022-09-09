<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\Tests\App\MessageHandler;

use Sofyco\Bundle\JwtAuthenticatorBundle\Message\AuthenticationSuccess;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

#[AsMessageHandler]
final class AuthenticationSuccessHandler
{
    public function __invoke(AuthenticationSuccess $message): void
    {
        if ('expired' === $message->userIdentifier) {
            throw new CustomUserMessageAuthenticationException('security.session.inactive');
        }
    }
}
