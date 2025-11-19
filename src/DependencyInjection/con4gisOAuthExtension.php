<?php
/*
 * This file is part of con4gis, the gis-kit for Contao CMS.
 * @package con4gis
 * @version 8
 * @author con4gis contributors (see "authors.txt")
 * @license LGPL-3.0-or-later
 * @copyright (c) 2010-2022, by Küstenschmiede GmbH Software & Design
 * @link https://www.con4gis.org
 */

namespace con4gis\OAuthBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\FileLoader;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;


/**
 * Class con4gisOAuthExtension.
 */
class con4gisOAuthExtension extends Extension
{
    /**
     * Loads a specific configuration.
     * @param $configs
     * @param $container
     * @throws \InvalidArgumentException When provided tag is not defined in this extension
     * @throws \Exception
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);
        $container->setParameter($this->getAlias(), $config);

        $loader = new YamlFileLoader(
            $container,
            new FileLocator(__DIR__.'/../Resources/config')
        );
        $loader->load('services.yml');

        $rootKey = $this->getAlias();

        $container->setParameter($rootKey.'.oidc.client_id', $config['oidc']['client_id']);
        $container->setParameter($rootKey.'.oidc.client_secret', $config['oidc']['client_secret']);
        $container->setParameter($rootKey.'.oidc.auth_server_url', $config['oidc']['auth_server_url']);
        $container->setParameter($rootKey.'.oidc.realm', $config['oidc']['realm']);
        $container->setParameter($rootKey.'.oidc.secured_frontend', $config['oidc']['secured_frontend']);
    }

    /**
     * {@inheritdoc}
     */
    public function getAlias(): string
    {
        return "con4gis_oauth";
    }
}