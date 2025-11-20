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

$cbClass = con4gis\OAuthBundle\Classes\OAuthCallback::class;

$GLOBALS['TL_DCA']['tl_module']['palettes']['o_auth_login_module'] = '{title_legend},name,type,c4g_oauth_type,c4g_oauth_btn_name,c4g_oauth_reg_groups,c4g_oauth_member_mapping;';

$GLOBALS['TL_DCA']['tl_module']['fields']['c4g_oauth_type'] = array
(
    'label'                   => &$GLOBALS['TL_LANG']['tl_module']['c4g_oauth']['fields']['type'],
    'exclude'                 => true,
    'filter'                  => false,
    'inputType'               => 'select',
    'options'                 => [
        '/oidc/login'               => &$GLOBALS['TL_LANG']['tl_module']['c4g_oauth']['fields']['type_oidc'],
    ],
    'default'                 => 'oidc',
    'eval'                    => ['submitOnChange' => false, 'mandatory' => true, 'tl_class' => 'clr'],
    'sql'                     => "varchar(32) NOT NULL default ''",
);

$GLOBALS['TL_DCA']['tl_module']['fields']['c4g_oauth_btn_name'] = array
(
    'label'                   => &$GLOBALS['TL_LANG']['tl_module']['c4g_oauth']['fields']['btn_name'],
    'exclude'                 => true,
    'filter'                  => false,
    'inputType'               => 'text',
    'default'                 => 'Login',
    'eval'                    => ['submitOnChange' => false, 'mandatory' => true],
    'sql'                     => "varchar(256) NOT NULL default ''",
);

$GLOBALS['TL_DCA']['tl_module']['fields']['c4g_oauth_reg_groups'] = array
(
    'label'                   => &$GLOBALS['TL_LANG']['tl_module']['c4g_oauth']['fields']['oauth_reg_groups'],
    'exclude'                 => true,
    'inputType'               => 'checkbox',
    'foreignKey'              => 'tl_member_group.name',
    'eval'                    => array('multiple'=>true),
    'sql'                     => "blob NULL",
    'relation'                => array('type'=>'hasMany', 'load'=>'lazy')
);

$GLOBALS['TL_DCA']['tl_module']['fields']['c4g_oauth_member_mapping'] = array
(
    'label'                   => &$GLOBALS['TL_LANG']['tl_module']['c4g_oauth']['fields']['memberMapping'],
    'sorting'                 => true,
    'search'                  => true,
    'inputType'               => 'multiColumnWizard',
    'default'                 => 'a:0:{}',
    'sql'                     => 'blob NOT NULL default \'a:0:{}\'',
    'eval'                    => array(
        'columnFields' => array(
            'contaoField' => array(
                'label'                   => &$GLOBALS['TL_LANG']['tl_module']['c4g_oauth']['fields']['contaoField'],
                'filter'                  => false,
                'inputType'               => 'select',
                'options_callback'        => array($cbClass, 'oauthMemberMappingOptions'),
                'eval'                    => array('tl_class' => 'w50'),
            ),
            'oauthField' => array(
                'label'                   => &$GLOBALS['TL_LANG']['tl_module']['c4g_oauth']['fields']['oauthField'],
                'sorting'                 => true,
                'search'                  => true,
                'inputType'               => 'text',
                'default'                 => '',
                'eval'                    => array('tl_class' => 'w50'),
            ),
        ),
    ),
);