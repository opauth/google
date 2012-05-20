<?php
/**
 * Google strategy for Opauth
 * based on https://developers.google.com/accounts/docs/OAuth2
 * 
 * More information on Opauth: http://opauth.org
 * 
 * @copyright		Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link 			http://opauth.org
 * @package			Opauth.Google
 * @license			MIT License
 */

/**
 * Google strategy for Opauth
 * based on https://developers.google.com/accounts/docs/OAuth2
 * 
 * @package			Opauth.Google
 */
class Google extends OpauthStrategy{
	
	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = array('client_id', 'client_secret');
	
	/**
	 * Optional config keys, without predefining any default values.
	 */
	public $optionals = array('redirect_uri', 'scope', 'state', 'access_type', 'approval_prompt');
	
	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'email');
	 */
	public $defaults = array(
		'redirect_uri' => '{complete_url_to_strategy}oauth2callback',
		'scope' => 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email'
	);
	
	/**
	 * Auth request
	 */
	public function request(){
		$url = 'https://accounts.google.com/o/oauth2/auth';
		$params = array(
			'client_id' => $this->strategy['client_id'],
			'redirect_uri' => $this->strategy['redirect_uri'],
			'response_type' => 'code',
			'scope' => $this->strategy['scope']
		);

		foreach ($this->optionals as $key){
			if (!empty($this->strategy[$key])) $params[$key] = $this->strategy[$key];
		}
		
		$this->redirect($url.'?'.http_build_query($params));
	}
	
	/**
	 * Internal callback, after Facebook's OAuth
	 */
	public function oauth2callback(){
		if (array_key_exists('code', $_GET) && !empty($_GET['code'])){
			$code = $_GET['code'];
			$url = 'https://accounts.google.com/o/oauth2/token';
			$params = array(
				'code' => $code,
				'client_id' => $this->strategy['client_id'],
				'client_secret' => $this->strategy['client_secret'],
				'redirect_uri' => $this->strategy['redirect_uri'],
				'response_type' => 'code',
				'grant_type' => 'authorization_code'
			);
			$response = $this->serverPost($url, $params, null, $headers);
			
			print_r($response);
			print_r($headers);
			exit();
			
			parse_str($response, $results);

			if (!empty($results) && !empty($results['access_token'])){
				$me = $this->me($results['access_token']);
				
				$this->auth = array(
					'provider' => 'Facebook',
					'uid' => $me->id,
					'info' => array(
						'name' => $me->name,
						'image' => 'https://graph.facebook.com/'.$me->id.'/picture?type=square'
					),
					'credentials' => array(
						'token' => $results['access_token'],
						'expires' => date('c', time() + $results['expires'])
					),
					'raw' => $me
				);
				
				if (!empty($me->email)) $this->auth['info']['email'] = $me->email;
				if (!empty($me->username)) $this->auth['info']['nickname'] = $me->username;
				if (!empty($me->first_name)) $this->auth['info']['first_name'] = $me->first_name;
				if (!empty($me->last_name)) $this->auth['info']['last_name'] = $me->last_name;
				if (!empty($me->location)) $this->auth['info']['location'] = $me->location->name;
				if (!empty($me->link)) $this->auth['info']['urls']['facebook'] = $me->link;
				if (!empty($me->website)) $this->auth['info']['urls']['website'] = $me->website;
				
				/**
				 * Missing optional info values
				 * - description
				 * - phone: not accessible via Facebook Graph API
				 */
				
				$this->callback();
			}
			else{
				$error = array(
					'provider' => 'Facebook',
					'code' => 'access_token_error',
					'message' => 'Failed when attempting to obtain access token',
					'raw' => $headers
				);

				$this->errorCallback($error);
			}
		}
		else{
			$error = array(
				'provider' => 'Facebook',
				'code' => $_GET['error'],
				'message' => $_GET['error_description'],
				'raw' => $_GET
			);
			
			$this->errorCallback($error);
		}
	}
	
	/**
	 * Queries Facebook Graph API for user info
	 *
	 * @param string $access_token 
	 * @return array Parsed JSON results
	 */
	private function me($access_token){
		$me = $this->httpRequest('https://graph.facebook.com/me?access_token='.$access_token);
		if (!empty($me)){
			return json_decode($me);
		}
	}
}