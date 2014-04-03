<?php

/**
 * Google strategy for Opauth
 * based on https://developers.google.com/accounts/docs/OAuth2
 *
 * More information on Opauth: http://opauth.org
 *
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.GoogleStrategy
 * @license      MIT License
 */

namespace Opauth\Google\Strategy;

use Opauth\Opauth\AbstractStrategy;

/**
 * Google strategy for Opauth
 * based on https://developers.google.com/accounts/docs/OAuth2
 *
 * @package            Opauth.Google
 */
class Google extends AbstractStrategy
{

    /**
     * Compulsory config keys, listed as unassociative arrays
     */
    public $expects = array('client_id', 'client_secret');

    /**
     * Optional config keys, without predefining any default values.
     */
    public $optionals = array('scope', 'state', 'access_type', 'approval_prompt');

    /**
     * Optional config keys with respective default values, listed as associative arrays
     * eg. array('scope' => 'email');
     */
    public $defaults = array(
        'scope' => 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email'
    );

    public $responseMap = array(
        'name' => 'name',
        'uid' => 'id',
        'info.name' => 'name',
        'info.email' => 'email',
        'info.first_name' => 'given_name',
        'info.last_name' => 'family_name',
        'info.image' => 'picture'
    );

    /**
     * Auth request
     */
    public function request()
    {
        $url = 'https://accounts.google.com/o/oauth2/auth';
        $params = array(
            'client_id' => $this->strategy['client_id'],
            'redirect_uri' => $this->callbackUrl(),
            'response_type' => 'code',
            'scope' => $this->strategy['scope']
        );
        $params = $this->addParams($this->optionals, $params);

        $this->redirect($url, $params);
    }

    /**
     * Internal callback, after OAuth
     */
    public function callback()
    {
        if (empty($_GET['code'])) {
            return $this->error('Error on OAuth2 callback.', 'oauth2callback_error', $_GET);
        }

        $response = $this->accessToken($_GET['code']);
        $results = json_decode($response);

        if (empty($results->access_token)) {
            return $this->error('Failed when attempting to obtain access token.', 'access_token_error', $response);
        }

        $params = array('access_token' => $results->access_token);
        $userinfo = $this->http->get('https://www.googleapis.com/oauth2/v1/userinfo', $params);

        if (empty($userinfo)) {
            return $this->error('Failed when attempting to query for user information.', 'userinfo_error');
        }

        $userinfo = $this->recursiveGetObjectVars(json_decode($userinfo));

        $response = $this->response($userinfo);
        $response->credentials = array(
            'token' => $results->access_token,
            'expires' => date('c', time() + $results->expires_in)
        );
        if (!empty($results->refresh_token)) {
            $response->credentials['refresh_token'] = $results->refresh_token;
        }
        $response->setMap($this->responseMap);
        return $response;
    }

    protected function accessToken($code)
    {
        $params = array(
            'code' => $code,
            'client_id' => $this->strategy['client_id'],
            'client_secret' => $this->strategy['client_secret'],
            'redirect_uri' => $this->callbackUrl(),
            'grant_type' => 'authorization_code'
        );
        return $this->http->post('https://accounts.google.com/o/oauth2/token', $params);
    }
}
