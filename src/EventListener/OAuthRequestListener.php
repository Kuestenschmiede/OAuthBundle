<?php

namespace con4gis\OAuthBundle\EventListener;

use Contao\CoreBundle\Exception\RedirectResponseException;
use Contao\CoreBundle\Framework\ContaoFramework;
use Contao\CoreBundle\Routing\ScopeMatcher;
use Contao\FrontendUser;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;

class OAuthRequestListener
{
    public function __construct(
        private ContaoFramework $framework,
        private ScopeMatcher $scopeMatcher,
        private string $securedFrontend
    ) {
    }

    public function __invoke(RequestEvent $event, $eventName, EventDispatcherInterface $eventDispatcher)
    {
        if ($this->securedFrontend === "false") {
            return;
        }

        $request = $event->getRequest();
        $requestPath = $request->getPathInfo();

        if (str_starts_with($requestPath, "/contao") && $this->scopeMatcher->isBackendRequest($request)) {
            // ignore Contao BE requests
            return;
        }

        $this->framework->initialize();
        $user = FrontendUser::getInstance();

        $requestHeaders = $request->headers->all();

        if (in_array("contao/crawler", $requestHeaders['user-agent'])) {
            return;
        }

        if (!str_starts_with($requestPath, "/oidc/login")) {
            if ($user === null || !$user->c4gOAuthMember) {
                // no OAuth user given
                // redirect to log in form
                throw new RedirectResponseException("/oidc/login");
            }
        }
    }
}