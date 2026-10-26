<?php

namespace con4gis\OAuthBundle\EventListener;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

#[AsEventListener(event: 'kernel.request', priority: 256)]
class CrawlerSecretValidationListener
{
    public function __construct(
        private string $crawlerSecret
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();

        $userAgent = $request->headers->get('User-Agent', '');

        if (str_contains($userAgent, 'Contao Crawler') || str_contains($userAgent, 'Escargot')) {

            $providedSecret = $request->headers->get('X-Contao-Crawler-Secret');

            if ($providedSecret !== $this->crawlerSecret) {
                throw new AccessDeniedHttpException('Ungültiger Crawler-Zugriff (Secret fehlerhaft).');
            }
        }
    }
}
