<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\Tests\App;

use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

final class Kernel extends \Symfony\Component\HttpKernel\Kernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        yield new \Symfony\Bundle\FrameworkBundle\FrameworkBundle();
        yield new \Symfony\Bundle\SecurityBundle\SecurityBundle();
        yield new \Sofyco\Bundle\JwtAuthenticatorBundle\JwtAuthenticatorBundle();
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->import('config/config.yaml');
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('index', '/')->controller(__CLASS__);
    }

    public function __invoke(#[CurrentUser] UserInterface $user): JsonResponse
    {
        return new JsonResponse(['user' => $user->getUserIdentifier()]);
    }
}
