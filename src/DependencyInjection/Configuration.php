<?php
/**
 * This file is part of con4gis,
 * the gis-kit for Contao CMS.
 *
 * @package   	con4gis
 * @version        8
 * @author  	    con4gis contributors (see "authors.txt")
 * @license 	    LGPL-3.0-or-later
 * @copyright 	Küstenschmiede GmbH Software & Design
 * @link              https://www.con4gis.org
 *
 */

namespace con4gis\OAuthBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public const ROOT_KEY = 'con4gis_oauth';

    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder(self::ROOT_KEY);

        $treeBuilder->getRootNode()
            ->children()
                ->arrayNode('oidc')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('client_id')
                            ->cannotBeEmpty()
                            ->defaultValue('***')
                        ->end()
                        ->scalarNode('client_secret')
                            ->cannotBeEmpty()
                            ->defaultValue('***')
                        ->end()
                        ->scalarNode('auth_server_url')
                            ->cannotBeEmpty()
                            ->defaultValue('http://localhost/auth')
                        ->end()
                        ->scalarNode('realm')
                            ->cannotBeEmpty()
                            ->defaultValue('master')
                        ->end()
                        ->booleanNode('secured_frontend')
                            ->defaultFalse()
                        ->end()
                    ->end()
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}