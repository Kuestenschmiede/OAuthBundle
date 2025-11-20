<?php

namespace con4gis\OAuthBundle\EventListener;

use Contao\CoreBundle\Exception\RedirectResponseException;
use Contao\CoreBundle\Framework\ContaoFramework;
use Contao\FrontendUser;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;

class OAuthRequestListener
{
    public function __construct(
        private ContaoFramework $framework,
        private string $securedFrontend
    ) {
    }

    public function __invoke(RequestEvent $event, $eventName, EventDispatcherInterface $eventDispatcher)
    {
        if (!$event->isMainRequest()) {
            // only execute on main request
            return;
        }

        $request = $event->getRequest();

        if (str_contains($request->getUri(), "/contao")) {
            // ignore Contao BE requests
            return;
        }

        $this->framework->initialize();
        $user = FrontendUser::getInstance();

        if ($this->securedFrontend !== "false" && !str_contains($request->getUri(), "/oidc/login")) {
            if ($user === null || !$user->c4gOAuthMember) {
                // no OAuth user given
                // redirect to log in form
                throw new RedirectResponseException("/oidc/login");
            }
        }
    }
}