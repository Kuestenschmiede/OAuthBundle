<?php
/*
 * This file is part of con4gis, the gis-kit for Contao CMS.
 * @package con4gis
 * @version 8
 * @author con4gis contributors (see "authors.txt")
 * @license LGPL-3.0-or-later
 * @copyright (c) 2010-2021, by Küstenschmiede GmbH Software & Design
 * @link https://www.con4gis.org
 */

$array = &$GLOBALS['TL_LANG']['tl_module']['c4g_oauth']['fields'];
$array['type'] = array('Loginanbieter', 'Hier den Anbieter auswählen, welcher für den Login genutzt werden soll.');
$array['type_oidc'] = 'OpenID Connect';
$array['btn_name'] = array('Beschriftung des Login Buttons', 'Hier kann ein Buttontext für die Anmeldung hinterlegt werden.');