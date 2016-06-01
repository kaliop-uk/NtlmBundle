This bundle is in development

Description
===========
This bundle sets up the NTLM authentication provider for your application. If there is NTLM data 
provided by the browser, then the application will try and authenticate the provided username against 
your user provider/chain user providers

Requirements
============

* Symfony > 2.0

* A way to retrieve the password of a user given his/her username, eg.
    - a Samba installation with the user db installed on the webserver
    - direct access to the user accounts database (with usernames and passwords)
    - a Samba installation which can communicate to the AD server to validate user credentials 

Installation
============

1. Use Composer to add the bundle to your application

2. Add this bundle to your application's kernel:

        // app/AppKernel.php

        public function registerBundles()
        {
            return array(
                // ...
                new BrowserCreative\NtlmBundle\BrowserCreativeNtlmBundle(),
                // ...
            );
        }


3. Update your security.yml:

        security:
            factories:
                - "%kernel.root_dir%/../vendor/bundles/BrowserCreative/NtlmBundle/Resources/config/security_factories.xml"

            providers:
                ...

            firewalls:
                secured_area:
                    pattern: ^/
                    ntlm_protocol:
                        target: <the auth target name>
                        domain: <auth domain. ex: ADDOMAIN>
                        server: <auth server. ex: INTRANET>
                        dns_domain: <auth domain fqdn. ex: addomain.local>
                        dns_server: <auth server fqdn. ex: intranet.addomain.local>
                        redirect_to_login_form_on_failure: true
                        ntlm_addresses: [ ...list of ip addresses authorized to do NTLM auth... ]
                        
                        token_validator: "the service id of a token validator"
                    ntlm_form_login:
                        provider: chain_provider
                        remember_me_parameter: _remember_me
                    logout: ~
                    anonymous: true
            
            ...

4. Set up the token validator used in the security.yml definition: ...

5. Optional: set the following 2 parameters:

        parameters:
            browser_detection.mobile: 'regexp...'
            browser_detection.desktop 'regexp...'

When set, they will be matched against the user-agent string from the browser:
- any mobile browser will not use NTLM auth (i.e. a blacklist)
- only desktop browsers will use NTLM auth (i.e. a whitelist; not setting it means 'all except the mobile ones')

Notes
=====
* The two authentication providers (NtlmProtocolAuthenticationProvider, NtlmFormLoginAuthenticationProvider) pass 
tokens to the user provider instead of the username. Feel free to change this back, it's just that our User Providers 
require the tokens because they rely on the password to access the database (LDAP)
