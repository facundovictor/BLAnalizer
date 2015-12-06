# BLAnalizer
Useful script to get a report of SMTP servers about their blacklisted status.
The scripts uses a "neutrinoapi" service to obtain the data.

Requirements:

    * PHP 5.X.X
    * Neutrinoapi account for 'host-reputation'
    * Outgoing SMTP service configured.

How to use it?

    1) Download the scripts *BLAnalyzer.php* and *BLA_configuration.conf*.
    or use git:

        git clone https://github.com/facundovictor/BLAnalizer.git

    2) Protect the file:

        chmod 400 BLAnalizer.php
        chmod 600 BLA_configuration.conf

    3) Configure script using the file *BLA_configuration.conf*:

        $SMTP_Servers:  It's an array of IP/FQDN of SMTP servers that you
                        want to get the report about their blacklisted status.

        $TIME_BETWEEN_API_QUERY:    Amount of seconds that the script will
                                    wait after every API request. A time value
                                    less than 15 may ban you from the API.

        $ADMIN_MAIL:    Mail where the report will be sent.

        $ADMIN_NAME:    Name of the administrator.

        $MAIL_SUBJECT:  Subject of the report's mail.

        $BA_FROM:   Mail From.

        $BA_NAME:   Script name, used as a BA_FROM description.

        $API_URL:   'https://neutrinoapi.com/host-reputation';

        $API_USER_ID:   Your user id for the *neutrinoapi*.

        $API_KEY:   Your key for the *neutrinoapi*.

        $LISTS_To_Ignore:   List of black lists to ignore. By default, some
                            lists are ignored just because they were annoying
                            and useless.

    4) Configure a cron task to finally configure the digest:

        Edit your /etc/crontab file and add the following line:

            30 2 * * * <user> /usr/bin/php -q /<path_to_scripts/BLAnalyser.php > /dev/null


