# Login with Verimi Integration Guide


## Prelimaries

Before you start you should have:

- [ ] A personal or organizational client certificate and the corresponding private key and the password for the keystore. This items are provided by Verimi. 
- [ ] A client_id and the corresponding client_secret. This items are provided by Verimi.
- [ ] Read the Verimi documentation at [https://ntegration.verimi.de/html/sdk.html](https://integration.verimi.de/html/sdk.html#)
- [ ] Created a truststore (in PKCS12 format) that contains the complete certificate chain to Verimi's (UAT-)environment



## Preperation

-  [ ] Import the provided client certificate and private key into your browser and make sure that the client certificate is presented by the browser when you access:
	- Verimi’s Partner portal to manage technical settings at [https://selfportal.uat.verimi.cloud/login](https://selfportal.uat.verimi.cloud/login). Your credentials are your *client_id* and the *client_secret*.
	- Verimis’s (UAT-)environment at [https://web.uat.verimi.cloud/](https://web.uat.verimi.cloud/)
	- Verimi’s Mailhog at [https://mailhog.uat.verimi.cloud](https://mailhog.uat.verimi.cloud/)

- [ ] Create some test users in the (UAT-) environment. To do this, access [web.uat.verimi.cloud/registration.html#/?clientId=](https://web.uat.verimi.cloud/registration.html#/?clientId=%3Cyour%20client_id%3E)`<your client_id>`. To activate the test users, you need to access Verimi’s Mailhog to get access to the activatation link for the test-users
- [ ] Make sure that the URL of your AM is in the list of Whitelisted URIs (including the service parameter)
- [ ] Decide whether you want to use 2FA authentication (even Verimi’s UAT-Environment can send you SMS messages).



## ForgeRock Access Management 

In order to use Login with Verimi you should configure FR AM in the following way:

- If needed, create a dedicated realm (in my case I did not do this).
- If needed, extend AMs user-profile by an attribute that should contain Verimi’s ID of a user (for my tests I used postalAddress to keep it simple).
- Import the following authentication-tree nodes into the `<deplyomentURI>`/WEB_INF/lib directory:
	- VerimiLogin (VerimiLogin-0.0.0.jar)
	- authByAttr (authByAttr-1.0.0-SNAPSHOT.jar)
	- promote-to-session (promote-to-session-node-1.0.0-SNAPSHOT.jar)
	- Debug Node (debug-node-6.0.0.jar) mights also be useful
- Restart AM after copying the nodes
- Create an Authentication tree called (e.g.) VerimiLogin which looks similar to:

![Verimi Auth Tree](./VerimiLogin/example.png?raw=true "Verimi Auth Tree")
 
- Configure the VerimiLogin node as follows:
	- `Wellknowm URL`: [https://api.uat.verimi.cloud/.well-known/openid-configuration](https://api.uat.verimi.cloud/.well-known/openid-configuration) (in the current version of the node this parameter is not used, but it’s necessary to verify the signature of the JWTs).
	- `URL of Verimi’s API` [api.uat.verimi.cloud/dipp/api](https://api.uat.verimi.cloud/dipp/api)
	- `Redirect URL` [https://login.openrock.org:8443/openam/XUI/?service=VerimiLogin](https://login.openrock.org:8443/openam/XUI/?service=VerimiLogin). This URL needs to be whitelisted in the partner portal and must be same as used for the login (see below).
	- `client_id`, `client_secret` should be obvious 
	- List of requested scopes: `name`  `emailaddress`. The configuration of this list is currently not evaluated, the values for the scopes name, email and address are currently propagated into the session anyway. The claim values are propagated as verimi`<claim-name>` into the shared state and than into session variables by the promote-to-session node. 
	- Token issues (as present in the `iss` claim): [https://web.uat.verimi.cloud/](https://web.uat.verimi.cloud/) 
	- `Truststore`,`truststore password`, `keystore`, `keystore password` should be obvious 
	-  `Timeout` and `connection timeout` should be kept as is for the moment.
	- `Shared-state variable for Verimi’s ID` must match the sharedStateVar in the authByAttr node. This variable is used to identify and authenticate the local user
- Configure the authByAttr nodes as follows:
	- `searchAttribute`: name of the profile attribute that store the Verimi ID.
	- `sharedStateVar`: name of the shared-state variable where the current value of the Verimi ID can be picked up.
	- `redirectURL`: URL to redirect to browser to after successful authentication. This would be either some local URL (e.g. User-Dashbaord) or a local URL to start an federation flows where AM acts as OP or IdP.
- Configure the promote-to-session node as follows:
	- For each scope you request (as said this current hard-coded to email, name and address), add a key `verimi<claim-name>` with the value of the session attribute which should be propagated to the RP or SP. To make this session properties accessable, you need also to whitelist the values in Global Servies -> Session Property Whitelist Service. 
- Configure you „Login with Verimi“ Buttons as follows:
	- [https://web.uat.verimi.cloud/oauth2/auth#login/&authIndexType=service&authIndexValue=VerimiLogin?response_type=code&scope=login%20openid%20name%20address%20email&client_id](https://web.uat.verimi.cloud/oauth2/auth#login/&authIndexType=service&authIndexValue=VerimiLogin?response_type=code&scope=login%20openid%20name%20address%20email&client_id)[=<client_id>&redirect_uri=](https://web.uat.verimi.cloud/oauth2/auth?response_type=code&scope=login%20openid%20name%20address%20email&client_id=forgerock&redirect_uri=http://localhost:8080/openam/XUI/?service=VerimiLogin#login/&authIndexType=service&authIndexValue=VerimiLogin)[<your AM URI incl. service-parameters>](https://web.uat.verimi.cloud/oauth2/auth?response_type=code&scope=login%20openid%20name%20address%20email&client_id=forgerock&redirect_uri=%3Cyour%20AM%20URI%20incl.%20service-parameters%3E). Make sure that the `redirect_uri` is whitelisted in Verimi’s Partner Portal and matches the `redict_uri` value you have configured in the Verimi node.

##  Test the Integration

Since registration is not yet implemented, you need to manually link the accounts together. To do this:

- Create a test-user as described above 
- Try to login with the newly created test-user, which will not work. Find the `verimiId` in the logfile (see below).
- Add the value of the `verimiId` to the test-users profileattribute you have configured, and re-run the test. This should now work.



After everything is configured you should get log-output (in Tomcat’s catalina.out) similar to this:

	[DebugNode]: 20:12:24 03/11/2019
	---------------------------------------
	Shared state        : { "realm": "/", "authLevel": 0 }
	Transient state     : {  }
	Request headers     : {accept=[application/json, text/javascript, _/_; q=0.01], accept-api-version=[protocol=1.0,resource=2.1], accept-encoding=[gzip, deflate], accept-language=[de-DE], cache-control=[no-cache], connection=[keep-alive], content-length=[0], content-type=[application/json], dnt=[1], host=[localhost:8080], origin=[[http://localhost:8080], referer=[http://localhost:8080/openam/XUI/?code=rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk&scope=openid%20login%20address%20name%20email&service=VerimiLogin&state=97bb9915-8bc6-473d-994f-aa82c765d505-generated](http://localhost:8080%5D,%20referer=%5Bhttp://localhost:8080/openam/XUI/?code=rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk&scope=openid%20login%20address%20name%20email&service=VerimiLogin&state=97bb9915-8bc6-473d-994f-aa82c765d505-generated)], user-agent=[Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:70.0) Gecko/20100101 Firefox/70.0], x-nosession=[true], x-password=[anonymous], x-requested-with=[XMLHttpRequest], x-username=[anonymous]}
	Request clientIp    : 0:0:0:0:0:0:0:1
	Request hostName    : localhost
	Request ssoTokenId  : 
	Request cookie      : {}
	Request parameters  : {authIndexValue=[VerimiLogin], code=[rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk], service=[VerimiLogin], scope=[openid login address name email], authIndexType=[service], realm=[/], state=[97bb9915-8bc6-473d-994f-aa82c765d505-generated]} 
	[VerimiLogin]: VerimiLogin started, reading configuration ...
	[VerimiLogin]: Verimi API URI: '[api.uat.verimi.cloud/dipp/api](https://api.uat.verimi.cloud/dipp/api)'.
	[VerimiLogin]: Redirect URL: '[localhost/openam/XUI/?service=VerimiLogin](http://localhost:8080/openam/XUI/?service=VerimiLogin)'.
	[VerimiLogin]: client_id: 'forgerock'.
	[VerimiLogin]: client_secret: '***'.
	[VerimiLogin]: Truststore file: '/Users/andre.posner/Documents/Forgerock/10_Activities/Verimi/verimiTruststore.p12'.
	[VerimiLogin]: Truststore password: '***'.
	[VerimiLogin]: Keystore file: '/Users/andre.posner/Documents/Forgerock/10_Activities/Verimi/andre.posner.4.verimi.uat.p12'.
	[VerimiLogin]: Keystore password: '***'.
	[VerimiLogin]: Timeout: '80'.
	[VerimiLogin]: connection timeout: '90'.
	[VerimiLogin]: VerimiIdAttribute: 'verimiId'.
	[VerimiLogin]: End reading configuration.
	[VerimiLogin]: ============================================
	[VerimiLogin]: Found query string: 'authIndexValue=[VerimiLogin], code=[rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk], service=[VerimiLogin], scope=[openid login address name email], authIndexType=[service], realm=[/], state=[97bb9915-8bc6-473d-994f-aa82c765d505-generated]' in request; will extract auth code ...
	[VerimiLogin]: Found auth code: 'rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk' in request.
	[VerimiLogin]: private key alias: 'andre posner'.
	[VerimiLogin]: Request URI: '[api.uat.verimi.cloud/dipp/api/oauth2/token?grant_type=authorization_code&code=rqdLg…ezIk&redirect_uri=http:…ogin](https://api.uat.verimi.cloud/dipp/api/oauth2/token?grant_type=authorization_code&code=rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fopenam%2FXUI%2F%3Fservice%3DVerimiLogin)'.
	[VerimiLogin]: Request header: 'name','value': 'Content-Type', 'application/x-www-form-urlencoded'.
	[VerimiLogin]: Request header: 'name','value': 'Authorization', 'Basic Zm9yZ2Vyb2NrOkNaQ2p2dDkqVGFVSA=='.
	[VerimiLogin]: Response: '{"access_token":"4WjKgYGOr4DbhnBB9tKx0782MZksE8zgtXB9XkLfwMc.4YO_4Mv4hyMmpxgJFsRdxddVrQHQim6PxLRvQZRtHVE","expires_in":1799,"token_type":"bearer","scope":"openid login address name email","id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpYzo3NGFmZmRmYS0xOTVjLTRiZTAtOGNlZi04ZjQ5OWI2ZTViNDciLCJ0eXAiOiJKV1QifQ.eyJhY3IiOiJsb2EuZGlwcC5kZWZhdWx0IiwiYWRkcmVzcyI6IntcImZvcm1hdHRlZFwiOlwiQmVyZ2lzY2hlIExhbmRzdHJhw59lIDY5NSwgNDA2MjkgRMO8c3NlbGRvcmYsIERldXRzY2hsYW5kXCIsXCJzdHJlZXRfYWRkcmVzc1wiOlwiQmVyZ2lzY2hlIExhbmRzdHJhw59lIDY5NVwiLFwibG9jYWxpdHlcIjpcIkTDvHNzZWxkb3JmXCIsXCJyZWdpb25cIjpcIlwiLFwicG9zdGFsX2NvZGVcIjpcIjQwNjI5XCIsXCJjb3VudHJ5XCI6XCJEZXV0c2NobGFuZFwifSIsImF0X2hhc2giOiIwNnBXSnhZdWFfZjhKZGFBVXRGMXhRIiwiYXVkIjpbImZvcmdlcm9jayJdLCJhdXRoX3RpbWUiOjE1NzI4MDgzNDIsImVtYWlsIjoiYW5kcmUucG9zbmVyQGZvcmdlcm9jay5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNTcyODEwMTQ1LCJpYXQiOjE1NzI4MDgzNDUsImlzcyI6Imh0dHBzOi8vd2ViLnVhdC52ZXJpbWkuY2xvdWQvIiwianRpIjoiNzZhMTVkOGEtOGE3ZS00ZTI4LTkwM2YtYjI1MjJhMTgyNDVmIiwibmFtZSI6IkFuZHJlIFBvc25lciIsIm5vbmNlIjoiIiwicmF0IjoxNTcyODA4MzM0LCJzdWIiOiIwOWZmM2ZmZi05MzNlLTQ5ZWQtODM5NC02ZWQ4M2ViNDQ2OGUifQ.Tm_57Ui5zALadT0p4qSF73O_MtIMk5-94A9tjea51fNvmeFLT5M_yEky7yYiCyZM9UKi4HWYs3rtsOt77pFkvMzVOYGJm7iRa1Woy4BHgbUp6Wb_QOm1jMt4g6CbLc4OG3ng6dAHjUgCY6zR111kDG72gxHTmfpcchanVxPRMOAHz1Efz_A69J3rCEJJtk2nYpU5J7ahzEjarzMMrFHvijyVBhUS48d7xApXKXRQ3EIOrfYCMcbQCuGXZskN7RpUlW4qSxpBuu2yRksqamat4Kq1Sg_MOZuqsW5r8s_Ks3jbn27fHVRq8dp9-AFXoH0MhUuMlKhFZFIYjazF8ZJSGg"}'.
	[VerimiLogin]: HTTP result code was 200/OK; will now validate response ...
	[VerimiLogin]: Found ID token (with JOSE header and signature): 'eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpYzo3NGFmZmRmYS0xOTVjLTRiZTAtOGNlZi04ZjQ5OWI2ZTViNDciLCJ0eXAiOiJKV1QifQ.eyJhY3IiOiJsb2EuZGlwcC5kZWZhdWx0IiwiYWRkcmVzcyI6IntcImZvcm1hdHRlZFwiOlwiQmVyZ2lzY2hlIExhbmRzdHJhw59lIDY5NSwgNDA2MjkgRMO8c3NlbGRvcmYsIERldXRzY2hsYW5kXCIsXCJzdHJlZXRfYWRkcmVzc1wiOlwiQmVyZ2lzY2hlIExhbmRzdHJhw59lIDY5NVwiLFwibG9jYWxpdHlcIjpcIkTDvHNzZWxkb3JmXCIsXCJyZWdpb25cIjpcIlwiLFwicG9zdGFsX2NvZGVcIjpcIjQwNjI5XCIsXCJjb3VudHJ5XCI6XCJEZXV0c2NobGFuZFwifSIsImF0X2hhc2giOiIwNnBXSnhZdWFfZjhKZGFBVXRGMXhRIiwiYXVkIjpbImZvcmdlcm9jayJdLCJhdXRoX3RpbWUiOjE1NzI4MDgzNDIsImVtYWlsIjoiYW5kcmUucG9zbmVyQGZvcmdlcm9jay5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNTcyODEwMTQ1LCJpYXQiOjE1NzI4MDgzNDUsImlzcyI6Imh0dHBzOi8vd2ViLnVhdC52ZXJpbWkuY2xvdWQvIiwianRpIjoiNzZhMTVkOGEtOGE3ZS00ZTI4LTkwM2YtYjI1MjJhMTgyNDVmIiwibmFtZSI6IkFuZHJlIFBvc25lciIsIm5vbmNlIjoiIiwicmF0IjoxNTcyODA4MzM0LCJzdWIiOiIwOWZmM2ZmZi05MzNlLTQ5ZWQtODM5NC02ZWQ4M2ViNDQ2OGUifQ.Tm_57Ui5zALadT0p4qSF73O_MtIMk5-94A9tjea51fNvmeFLT5M_yEky7yYiCyZM9UKi4HWYs3rtsOt77pFkvMzVOYGJm7iRa1Woy4BHgbUp6Wb_QOm1jMt4g6CbLc4OG3ng6dAHjUgCY6zR111kDG72gxHTmfpcchanVxPRMOAHz1Efz_A69J3rCEJJtk2nYpU5J7ahzEjarzMMrFHvijyVBhUS48d7xApXKXRQ3EIOrfYCMcbQCuGXZskN7RpUlW4qSxpBuu2yRksqamat4Kq1Sg_MOZuqsW5r8s_Ks3jbn27fHVRq8dp9-AFXoH0MhUuMlKhFZFIYjazF8ZJSGg'; split it ...
	[VerimiLogin]: Validation of response was successful, found Verimi ID: '09ff3fff-933e-49ed-8394-6ed83eb4468e'.
	[VerimiLogin]: Write Verimi ID: '09ff3fff-933e-49ed-8394-6ed83eb4468e' to shared state attribute: 'verimiId'.
	[DebugNode]: 20:12:25 03/11/2019
	---------------------------------------
	Shared state        : { "realm": "/", "authLevel": 0, "verimiId": "09ff3fff-933e-49ed-8394-6ed83eb4468e", "verimiEmail": "[andre.posner@forgerock.com](mailto:andre.posner@forgerock.com)", "verimiName": "Andre Posner", "verimiAddress": "{\"formatted\":\"Bergische Landstraße 695, 40629 Düsseldorf, Deutschland\",\"street_address\":\"Bergische Landstraße 695\",\"locality\":\"Düsseldorf\",\"region\":\"\",\"postal_code\":\"40629\",\"country\":\"Deutschland\"}" }
	Transient state     : {  }
	Request headers     : {accept=[application/json, text/javascript, _/_; q=0.01], accept-api-version=[protocol=1.0,resource=2.1], accept-encoding=[gzip, deflate], accept-language=[de-DE], cache-control=[no-cache], connection=[keep-alive], content-length=[0], content-type=[application/json], dnt=[1], host=[localhost:8080], origin=[[http://localhost:8080], referer=[http://localhost:8080/openam/XUI/?code=rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk&scope=openid%20login%20address%20name%20email&service=VerimiLogin&state=97bb9915-8bc6-473d-994f-aa82c765d505-generated](http://localhost:8080%5D,%20referer=%5Bhttp://localhost:8080/openam/XUI/?code=rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk&scope=openid%20login%20address%20name%20email&service=VerimiLogin&state=97bb9915-8bc6-473d-994f-aa82c765d505-generated)], user-agent=[Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:70.0) Gecko/20100101 Firefox/70.0], x-nosession=[true], x-password=[anonymous], x-requested-with=[XMLHttpRequest], x-username=[anonymous]}
	Request clientIp    : 0:0:0:0:0:0:0:1
	Request hostName    : localhost
	Request ssoTokenId  : 
	Request cookie      : {}
	Request parameters  : {authIndexValue=[VerimiLogin], code=[rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk], service=[VerimiLogin], scope=[openid login address name email], authIndexType=[service], realm=[/], state=[97bb9915-8bc6-473d-994f-aa82c765d505-generated]} 
	[authByAttr]: authByAttr started ...
	[authByAttr]: Configuration: search attribute: 'postalAddress'.
	[authByAttr]: Configuration: shared state attribute: 'verimiId'.
	[authByAttr]: Configuration: redirect URL: '[localhost/openam/XUI/?service=VerimiLogin](http://localhost:8080/openam/XUI/?service=VerimiLogin)'.
	[authByAttr]: Got pseudonym: '09ff3fff-933e-49ed-8394-6ed83eb4468e'.
	[authByAttr]: User Search: Searching  with BaseDN: 'dc=openam,dc=forgerock,dc=org'.
	[authByAttr]: User Search: Searching with Filter: '{postalAddress=[09ff3fff-933e-49ed-8394-6ed83eb4468e]}'.
	[authByAttr]: User Search: Searching with IDS: '{postalAddress=[09ff3fff-933e-49ed-8394-6ed83eb4468e]}'.
	[authByAttr]: User Search: Got results: 'IdSearchResults:
		Identities: [AMIdentity object: id=demo,ou=user,dc=openam,dc=forgerock,dc=org]
		Attributes: {AMIdentity object: id=demo,ou=user,dc=openam,dc=forgerock,dc=org={cn=[demo], createTimestamp=[20191103110138Z], employeeNumber=[0], modifyTimestamp=[20191103144346Z], inetUserStatus=[Active], uid=[demo], postalAddress=[09ff3fff-933e-49ed-8394-6ed83eb4468e], iplanet-am-user-auth-config=[[Empty]], objectClass=[iplanet-am-managed-person, inetuser, sunFederationManagerDataStore, sunFMSAML2NameIdentifier, inetorgperson, sunIdentityServerLibertyPPService, devicePrintProfilesContainer, iplanet-am-user-service, iPlanetPreferences, pushDeviceProfilesContainer, forgerock-am-dashboard-service, organizationalperson, top, kbaInfoContainer, person, sunAMAuthAccountLockout, oathDeviceProfilesContainer, webauthnDeviceProfilesContainer, iplanet-am-auth-configuration-service], sn=[demo], userPassword=[{SSHA512}7VdBtehILHAW3nD0lq7bqaJih9bAuEvfjMP3XHBHWBsCyJDSgW1Xe1U/ZmqUPBtE991AFtJG7CIpqwZtbcZB23PCNYK8HQVi]}}'.
	[authByAttr]: User Search: Found identities: '[AMIdentity object: id=demo,ou=user,dc=openam,dc=forgerock,dc=org]'.
	[authByAttr]: User attribute value '[09ff3fff-933e-49ed-8394-6ed83eb4468e]' for 'postalAddress'.
	[authByAttr]: Found user: demo
	[authByAttr]: All good => access granted!
	[authByAttr]: will forward the use to '[localhost/openam/XUI/?service=VerimiLogin](http://localhost:8080/openam/XUI/?service=VerimiLogin)'.
	[DebugNode]: 20:12:25 03/11/2019
	---------------------------------------
	Shared state        : { "realm": "/", "authLevel": 0, "verimiId": "09ff3fff-933e-49ed-8394-6ed83eb4468e", "verimiEmail": "[andre.posner@forgerock.com](mailto:andre.posner@forgerock.com)", "verimiName": "Andre Posner", "verimiAddress": "{\"formatted\":\"Bergische Landstraße 695, 40629 Düsseldorf, Deutschland\",\"street_address\":\"Bergische Landstraße 695\",\"locality\":\"Düsseldorf\",\"region\":\"\",\"postal_code\":\"40629\",\"country\":\"Deutschland\"}", "username": "demo", "userGotoParam": "[localhost/openam/XUI/?service=VerimiLogin](http://localhost:8080/openam/XUI/?service=VerimiLogin)" }
	Transient state     : [ unavailable ]
	Request headers     : {accept=[application/json, text/javascript, _/_; q=0.01], accept-api-version=[protocol=1.0,resource=2.1], accept-encoding=[gzip, deflate], accept-language=[de-DE], cache-control=[no-cache], connection=[keep-alive], content-length=[0], content-type=[application/json], dnt=[1], host=[localhost:8080], origin=[[http://localhost:8080], referer=[http://localhost:8080/openam/XUI/?code=rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk&scope=openid%20login%20address%20name%20email&service=VerimiLogin&state=97bb9915-8bc6-473d-994f-aa82c765d505-generated](http://localhost:8080%5D,%20referer=%5Bhttp://localhost:8080/openam/XUI/?code=rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk&scope=openid%20login%20address%20name%20email&service=VerimiLogin&state=97bb9915-8bc6-473d-994f-aa82c765d505-generated)], user-agent=[Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:70.0) Gecko/20100101 Firefox/70.0], x-nosession=[true], x-password=[anonymous], x-requested-with=[XMLHttpRequest], x-username=[anonymous]}
	Request clientIp    : 0:0:0:0:0:0:0:1
	Request hostName    : localhost
	Request ssoTokenId  : 
	Request cookie      : {}
	Request parameters  : {authIndexValue=[VerimiLogin], code=[rqdLgl7-uTFvZuf8SXaT0TswD7OjPPDlCy0jcN5UMVE.uk60brFKjmFX1G_yCQcUMwHWufXDy8U3sIyAW64ezIk], service=[VerimiLogin], scope=[openid login address name email], authIndexType=[service], realm=[/], state=[97bb9915-8bc6-473d-994f-aa82c765d505-generated]} 


