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

namespace con4gis\OAuthBundle\Classes;

use Contao\Database;
use Contao\MemberModel;

class LoginUserHandler
{

    private $db = null;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }
    
    public function addUser ($userArray, $loginRoute) {

        $feUser = MemberModel::findByUsername($userArray['username']);
        if (!$feUser) {
            $feUser = new MemberModel();
            $feUser->dateAdded = time();
        } else {
            $feUser->lastLogin = $feUser->currentLogin;
        }
        $feUser->c4gOAuthMember = 1;
        $feUser->login = 1;
        $feUser->tstamp = time();
        $feUser->currentLogin = time();
        $feUser->username = $userArray['username'];

        //add user to groups
        $loginModule = $this->db->prepare("SELECT * FROM tl_module WHERE c4g_oauth_type = ?")
            ->execute($loginRoute)->fetchAssoc();
        $feUserGroups = $feUser->groups;
        if ($feUserGroups && $feUserGroups != 'a:0:{}') {
            $feUserGroups = unserialize($feUserGroups);
            $loginGroups = unserialize($loginModule['c4g_oauth_reg_groups']);

            if (is_array($loginGroups)) {
                $missingGroups = array_diff($loginGroups, $feUserGroups);
                if ($missingGroups) {
                    foreach ($missingGroups as $missingGroup) {
                        $feUserGroups[] = $missingGroup;
                    }
                    $feUser->groups = serialize($feUserGroups);
                }
            }

        } else {
            $feUser->groups = $loginModule['c4g_oauth_reg_groups'];
        }

        //map additional member information
        $memberMappings = $loginModule['c4g_oauth_member_mapping'];
        if ($memberMappings && $memberMappings != 'a:0:{}') {
            $memberMappings = unserialize($memberMappings);
            foreach ($memberMappings as $memberMapping) {
                if ($memberMapping['contaoField'] == '0') {
                    break;
                }
                $contaoField = $memberMapping['contaoField'];
                $oauthField = $memberMapping['oauthField'];

                if (
                    array_key_exists($oauthField, $userArray)
                    && $userArray[$oauthField]
                ) {
                    $feUser->$contaoField = $userArray[$oauthField];
                }
            }
        }

        //save member
        $feUser->save();

        return $feUser;
    }
}