<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\DependencyInjection;

use Lcobucci\JWT;
use Sofyco\Bundle\JwtAuthenticatorBundle\Security\Encoder\JwtEncoder;
use Sofyco\Bundle\JwtAuthenticatorBundle\Security\Guard\TokenAuthenticator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\ConfigurableExtension;

final class JwtAuthenticatorExtension extends ConfigurableExtension
{
    protected function loadInternal(array $mergedConfig, ContainerBuilder $container): void
    {
        $signer = new Definition(JWT\Signer\Hmac\Sha256::class);
        $container->setDefinition(JWT\Signer::class, $signer);

        $key = new Definition(JWT\Signer\Key\InMemory::class, [$container->getParameter('kernel.secret')]);
        $key->setFactory([JWT\Signer\Key\InMemory::class, 'plainText']);
        $container->setDefinition(JWT\Signer\Key::class, $key);

        $configuration = new Definition(JWT\Configuration::class, [
            new Reference(JWT\Signer::class),
            new Reference(JWT\Signer\Key::class),
        ]);
        $configuration->setFactory([JWT\Configuration::class, 'forSymmetricSigner']);
        $container->setDefinition(JWT\Configuration::class, $configuration);

        $encoder = new Definition(JwtEncoder::class, [new Reference(JWT\Configuration::class), $mergedConfig['ttl']]);
        $container->setDefinition(JwtEncoder::class, $encoder);

        $authenticator = new Definition(TokenAuthenticator::class);
        $authenticator->setAutowired(true);
        $container->setDefinition(TokenAuthenticator::class, $authenticator);
    }
}
