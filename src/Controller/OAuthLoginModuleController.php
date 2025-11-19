<?php

namespace con4gis\OAuthBundle\Controller;

use Contao\CoreBundle\Controller\FrontendModule\AbstractFrontendModuleController;
use Contao\CoreBundle\Twig\FragmentTemplate;
use Contao\FrontendUser;
use Contao\ModuleModel;
use Contao\System;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class OAuthLoginModuleController extends AbstractFrontendModuleController
{
    protected function getResponse(FragmentTemplate $template, ModuleModel $model, Request $request): Response
    {
        System::loadLanguageFile('fe_c4g_oauth_login');

        $objUser = FrontendUser::getInstance();

        if ($objUser !== null) {
            $userId = $objUser->id;
            $template->loginStatus = $userId;
        } else {
            $template->loginStatus = false;
        }

        return $template->getResponse();
    }

}