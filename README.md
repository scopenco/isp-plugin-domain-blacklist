isp-plugin-domain-blacklist
===========================

Documentation
--------
ISPmanager plugin checks domain in local block list for events domain.edit, wwwdomain.edit, emaildomain.edit, user.edit and return error (in russian) if domain exist. The main goal is to prevent users to create domain of public resources like gmail, hotmail, google and redirect web/mail traffic to sniffer. This plugins should be on every shared hosting that use ISPmanager for security reasons.

Installing
----------
> cp -v etc/ispmgr_mod_domain_blacklist.xml /usr/local/ispmgr/etc/

> cp -v etc/blacklist.txt /usr/local/ispmgr/etc/

> cp -v etc/whitelist.txt /usr/local/ispmgr/etc/

> cp -v addon/domain_blacklist.py /usr/local/ispmgr/addon/

> killall -9 ispmgr

Testing
----------
Tested on CentOS 6.

Questions?
----------
If you have questions or problems getting things
working, first try searching wiki.

If all else fails, you can email me and I'll try and respond as
soon as I get a chance.

        -- Andrey V. Scopenco (andrey@scopenco.net)
