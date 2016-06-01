Roughly in order of importance:

- finish the tokenValidator based on the ntlm_auth helper
    - change the API if needed: allow TokenValidator to generate the challenge
      saee: http://comments.gmane.org/gmane.network.samba.general/157419

- test:
    - set up a path validated via ntlm + required user role => is the user redirected to form login ?
    - after a form (session) login, are the ntlm auth headers still sent to the browser on every page ?
    - if the user already has an anon session, are the ntlm auth headers still sent to the browser on every page ?
    - is there a need to keep sending ntlm auth headers if the auth fails (commented code which was in the entrypoint)? => can be done in the listener, probably 
    - does the ntlm firewall kick-in on accessing /logout ? it should probably not
    - does the logout listener work?
    - is it possible to force the browser to forget the NTLM credentials, upon logout?
    - is it correct to keep the firewall listener at 'remember me' position instead of 'http' ?

- integration with ez (customer's project):
    - miss the code/config to import a user via ldap if a new sso user is presented 

- what to return in ntlmToken->getCredentials ?

- more flexible config:
    - allow ranges for IPs

- try to avoid storing twice the ntlm data in the session (in _ntlm_auth and in the security token)

- set up 2 extra token validators based on smb binary helper and local db

- code refactoring:
    - rename the bundle to be in Kaliop namespace instead of BrowserCreative?
    - use a ResponseData class instead of an Array
    - make the Lib class use non-static methods
    - refactor classes which have 'protocol' in the name => remove it

- document the how and why of token validators

- document: how to set up browsers to allow ntlm auth for a site
    - IE intranet zone: ok for chrome, ie, edge
    - about:config for FF (but could not make it work so far)

- document / code a user provider which retrieves the user provider via ldap (take code from kaliop id mgmt bundle)

- check dead code and remove it if not used:
    * form login
    * custom triggering of login event ?
    * remember_me
    * logout listener
