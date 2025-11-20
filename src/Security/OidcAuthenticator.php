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

namespace con4gis\OAuthBundle\Security;

use Contao\CoreBundle\Framework\ContaoFramework;
use con4gis\OAuthBundle\Classes\LoginUserHandler;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\User\OAuthUser;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\ChainUserProvider;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Contao\System;

class OidcAuthenticator extends OAuth2Authenticator implements AuthenticationEntryPointInterface
{
    use TargetPathTrait;

    private $clientRegistry;
    private $em;
    private $router;
    private $framework;
    private $securedFrontend;
    private $userProvider;
    private $chainUserProvider;
    private $security;

    public function __construct(
        ContaoFramework $contaoFramework,
        ClientRegistry $clientRegistry,
        RouterInterface $router,
        EntityManagerInterface $em,
        $userProvider,
        ChainUserProvider $chainUserProvider,
        Security $security
    ) {
        $this->clientRegistry = $clientRegistry;
        $this->em = $em;
        $this->router = $router;
        $this->framework = $contaoFramework;
        $this->userProvider = $userProvider;
        $this->chainUserProvider = $chainUserProvider;
        $this->security = $security;
    }

    public function supports(Request $request): bool
    {
        // continue ONLY if the current ROUTE matches the check ROUTE
        return $request->attributes->get('_route') === 'connect_oidc_check';
    }

    public function authenticate(Request $request): Passport
    {
        $client = $this->clientRegistry->getClient('oidc');
        $accessToken = $this->fetchAccessToken($client);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function() use ($accessToken, $client) {

                $this->framework->initialize();

                $oidcUser = $this->getOidcClient()->fetchUserFromToken($accessToken);
                $oidcUser = $oidcUser->toArray();

                $userArray = [
                    'username' => $oidcUser['preferred_username']
                ];

                foreach ($oidcUser as $oidcUserAttrKey => $oidcUserAttrValue) {
                    $userArray[$oidcUserAttrKey] = $oidcUserAttrValue;
                }

                $loginUser = new LoginUserHandler();
                $feUser = $loginUser->addUser($userArray, '/oidc/login');

                $user = $this->chainUserProvider->loadUserByIdentifier($feUser->username);

                return $user;

            })
        );
    }

    /**
     * @return OAuth2ClientInterface
     */
    private function getOidcClient()
    {
        return $this->clientRegistry
            // "oidc" is the key used in config/knpu_oauth2_client.yml
            ->getClient('oidc');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath, Response::HTTP_TEMPORARY_REDIRECT);
        }

        return new RedirectResponse('/',
            Response::HTTP_TEMPORARY_REDIRECT
        );
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $message = strtr($exception->getMessageKey(), $exception->getMessageData());

        return new Response($message, Response::HTTP_FORBIDDEN);
    }

    /**
     * Called when authentication is needed, but it's not sent.
     * This redirects to the 'login'.
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new RedirectResponse(
            '/oidc/login',
            Response::HTTP_TEMPORARY_REDIRECT
        );
    }
}