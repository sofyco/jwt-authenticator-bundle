<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $builder = new TreeBuilder('jwt_authenticator');

        /** @var ArrayNodeDefinition $root */
        $root = $builder->getRootNode();

        $options = $root->children();
        $options->scalarNode('ttl')->defaultValue('+7 days')->end();

        return $builder;
    }
}
