<?php

namespace con4gis\OAuthBundle\Controller;

use http\Client;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Security\User\OAuthUserProvider;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Response;

class KeycloakController extends AbstractController
{
    private $clientRegistry;
    private $provider;
    private $security;

    public function __construct(
        ClientRegistry $clientRegistry,
        AbstractProvider $provider,
        Security $security
    ) {
        $this->clientRegistry = $clientRegistry;
        $this->provider = $provider;
        $this->security = $security;
    }
    /**
     * Link to this controller to start the "connect" process
     *
     * @Route("/oidc/login", name="connect_oidc_start")
     */
    public function connectAction()
    {
        // will redirect to sso!
        return $this->clientRegistry
            ->getClient('oidc') // key used in config/knpu_oauth2_client.yml
            ->redirect();
    }

    /**
     * After going to SSO, you're redirected back here
     * because this is the "redirect_route" you configured
     * in config/packages/knpu_oauth2_client.yaml
     *
     * @Route("/oidc/callback", name="connect_oidc_check")
     */
    public function connectCheckAction(Request $request) { }


    /**
     *
     * @Route("/oidc/logout", name="oidc_logout")
     */
    public function logoutAction(Request $request)
    {
        // TODO fix redirect after logout
        $baseAuthUrl = $this->provider->getBaseAuthorizationUrl();
        $logoutUrl = str_replace("auth", "logout", $baseAuthUrl);
        $logoutUrl .= "?redirect_uri=" . urlencode($request->getSchemeAndHttpHost());

        // TODO would be better if we could use some kind of callback to do this
        $this->security->logout(false);

        return new RedirectResponse($logoutUrl);
    }
}