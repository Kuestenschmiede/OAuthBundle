<?php
/*
 * This file is part of con4gis,
 * the gis-kit for Contao CMS.
 *
 * @package    con4gis
 * @version    8
 * @author     con4gis contributors (see "authors.txt")
 * @license    LGPL-3.0-or-later
 * @copyright  Küstenschmiede GmbH Software & Design
 * @link       https://www.con4gis.org
 */
namespace con4gis\OAuthBundle\ContaoManager;

use con4gis\OAuthBundle\con4gisOAuthBundle;
use Contao\CoreBundle\ContaoCoreBundle;
use Contao\ManagerPlugin\Bundle\Config\BundleConfig;
use Contao\ManagerPlugin\Bundle\Config\ConfigInterface;
use Contao\ManagerPlugin\Bundle\Parser\ParserInterface;
use Contao\ManagerPlugin\Bundle\BundlePluginInterface;
use Contao\ManagerPlugin\Config\ConfigPluginInterface;
use Contao\ManagerPlugin\Routing\RoutingPluginInterface;
use Contao\ManagerPlugin\Config\ContainerBuilder;
use Contao\ManagerPlugin\Config\ExtensionPluginInterface;
use Contao\ManagerPlugin\Dependency\DependentPluginInterface;
use KnpU\OAuth2ClientBundle\KnpUOAuth2ClientBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Config\Loader\LoaderResolverInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\HttpKernel\KernelInterface;

class Plugin implements BundlePluginInterface, ExtensionPluginInterface, RoutingPluginInterface, ConfigPluginInterface
{
    public function registerContainerConfiguration(LoaderInterface $loader, array $config)
    {
        $loader->load('@con4gisOAuthBundle/Resources/config/config.yml');
        $loader->load('@con4gisOAuthBundle/Resources/config/knpu_oauth2_client.yml');
        $loader->load(__DIR__.'/../Resources/config/services.yml');
    }

    /**
     * {@inheritdoc}
     */
    public function getRouteCollection(LoaderResolverInterface $resolver, KernelInterface $kernel)
    {
        return $resolver
            ->resolve(__DIR__.'/../Resources/config/routing.yml')
            ->load(__DIR__.'/../Resources/config/routing.yml')
            ;
    }

    /**
     * Gets a list of autoload configurations for this bundle.
     *
     * @param ParserInterface $parser
     *
     * @return ConfigInterface[]
     */
    public function getBundles(ParserInterface $parser)
    {
        return [
            BundleConfig::create(KnpUOAuth2ClientBundle::class),
            BundleConfig::create(con4gisOAuthBundle::class)
                ->setLoadAfter([ContaoCoreBundle::class, KnpUOAuth2ClientBundle::class])
        ];
    }

    /**
     * Allows a plugin to override extension configuration.
     *
     * @param string           $extensionName
     * @param array            $extensionConfigs
     * @param ContainerBuilder $container
     *
     * @return array
     */
    public function getExtensionConfig($extensionName, array $extensionConfigs, ContainerBuilder $container)
    {
        if ('security' !== $extensionName) {
            return $extensionConfigs;
        }

        foreach ($extensionConfigs as &$extensionConfig) {
            if (isset($extensionConfig['firewalls'])) {

                // Add own security authentication provider
                $extensionConfig['providers']['oauth'] = [
                    'id' => 'knpu.oauth2.user_provider'
                ];

                $extensionConfig['providers']['frontend_chain'] = [
                    'chain' => [
                        'providers' => ['oauth','contao.security.frontend_user_provider']
                    ]
                ];

                $offset = (int) array_search('frontend', array_keys($extensionConfig['firewalls']));

                $extensionConfig['firewalls']['contao_frontend']['custom_authenticators'] = [
                    'oidc_authenticator'
                ];
                unset($extensionConfig['firewalls']['contao_frontend']['request_matcher']);
                if ($container->getParameter('con4gis.oauth.oidc.secured') == 'true') {
                    $extensionConfig['access_control'][3]['roles'] = "ROLE_OAUTH_USER";

                    $extensionConfig['firewalls']['contao_frontend']['entry_point'] = 'oidc_authenticator';
                    $extensionConfig['firewalls']['contao_frontend']['pattern'] = '^/(?!oidc/login|oidc/login|contao)';
                    $extensionConfig['firewalls']['contao_frontend']['provider'] = 'frontend_chain';
//                    $extensionConfig['firewalls']['contao_frontend']['anonymous'] = false;
                } else {
                    // default to Contao authenticator if oidc is not set up
                    $extensionConfig['firewalls']['contao_frontend']['entry_point'] = "contao_login";
                }

                break;
            }
        }

        return $extensionConfigs;
    }

}