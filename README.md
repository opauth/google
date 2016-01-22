Opauth-Google
=============
[Opauth][1] strategy for Google authentication.

Implemented based on https://developers.google.com/accounts/docs/OAuth2 using OAuth 2.0.

http://path_to_opauth/google/oauth2callback`

   
3. Configure Opauth-Google strategy.

4. Direct user to `http://path_to_opauth/google` to authenticate


Strategy configuration
----------------------

Required parameters:

```php
<?php
'Google' => array(
	'client_id' => 'YOUR CLIENT ID',
	'client_secret' => 'YOUR CLIENT SECRET'
)
```

Optional parameters:
`scope`, `state`, `access_type`, `approval_prompt`


References
----------
- [Using OAuth 2.0 to Access Google APIs](https://developers.google.com/accounts/docs/OAuth2)
- [Using OAuth 2.0 for Login](https://developers.google.com/accounts/docs/OAuth2Login#scopeparameter)
- [Using OAuth 2.0 for Web Server Applications](https://developers.google.com/accounts/docs/OAuth2WebServer)

License
---------
Opauth-Google is MIT Licensed  
Copyright © 2012 U-Zyn Chua (http://uzyn.com)

[1]: https://github.com/uzyn/opauth
