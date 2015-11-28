<?php
// Black List Analyzer

        // List of smtp servers to analyze if they are black-listed.
        $SMTP_Servers;

        // Time between api querys. If the time is too short, the api will reject the query.
        $TIME_BETWEEN_API_QUERY = 25;

        // Mail where the digest will be sent.
        $ADMIN_MAIL = 'administrator@mydomain.com';

        // Administrator Name.
        $ADMIN_NAME = 'Admin User';

        // Mail Subject
        $MAIL_SUBJECT = 'Servers smtp status';

        // Black_Analyzer Mail From:
        $BA_FROM = 'root@mydomain.com';

        // Black_Analyzer custom name.
        $BA_NAME = 'BlackList-Analyzer';

        // API url.
        $API_URL = 'https://neutrinoapi.com/host-reputation';

        // API User Id.
        $API_USER_ID;

        // Api key
        $API_KEY;

        // List of black lists to ignor.
        $LISTS_To_Ignore;

        // Se incluye la configuracion del script.
        include_once "BLA_configuration.conf";

        // FUNCIONES ------------------------------------------------------------------------------------------------------

        /* get_BlackList_Result:
        *       Gets if each SMTP servre is black listed.
        *
        *  Parameters:
        *       $IP             --> SMTP server IP address.
        *       $API_URL
        *       $API_USER_ID
        *       $API_KEY
        *
        *  Returns:
        *       json --> {
        *               is-listed (boolean)     --> Is this host blacklisted.
        *               list-count (integer)    --> The number of DNSBL's the host is listed on.
        *               lists (array)           --> An array of objects for each DNSBL checked,
        *                                       each object can contain the following keys:
        *                                               is-listed - true if listed, false if not
        *                                               list-name - the name of the DNSBL
        *                                               list-host - the domain/hostname of the DNSBL
        *                                               txt-record - the TXT record returned for this listing (if listed)
        *       }
        */
        function get_BlackList_Result($IP, $API_URL, $API_USER_ID, $API_KEY){
                $req = new HttpRequest($API_URL, HttpRequest::METH_POST);
                $req->addPostFields(array('host' => "$IP", 'user-id' => $API_USER_ID, 'api-key' => $API_KEY));
                try {
                        $response_DATA = $req->send()->getBody();
                        $json_response_array = json_decode($response_DATA,true);
                        return $json_response_array;
                } catch (HttpException $ex) {
                        $error_response_array = array('error' => true, 'exception' => "$ex");
                        return $error_response_array;
                }

                return array('error' => true, 'exception' => 'get_BlackList_Result: unknown error');
        }

        /* not_Ignored:
        *       Given a black list, it determines if must be ignored
        *       according to the configured list to ignore
        *
        *  Parameters:
        *       $list           --> Black list to analyze
        *
        *  Returns:
        *       boolean         --> TRUE if must be ignored else returns FALSE.
        */
        function not_Ignored($list){
                global $LISTS_To_Ignore;
                if (isset($LISTS_To_Ignore)){
                        foreach ($LISTS_To_Ignore as $list_ignore){
                                if ($list['list-host'] == $list_ignore){
                                        return false;
                                }
                        }
                }
                return true;
        }

        /* get_BlackList_array:
        *       Given a list of black-lists, returns only those that has the
        *       'is-listed' field with value TRUE.
        */
        function get_BlackList_array($lists){
                $rta = array();
                foreach ($lists as $list){
                        if ($list['is-listed']){
                                if (not_Ignored($list)){
                                        array_push($rta, $list);
                                }
                        }
                }
                return $rta;
        }

        /* getHtmlListsTable:
        *       Given a list of black-lists, returns the information in a html
        *       table format. The table contains the headers 'Host', 'Name' and
        *       Info.
        */
        function getHtmlListsTable($lists){
                if (count($lists)>0){
                        $table="<table border=\"1\"><tr><th>Host</th><th>Name</th><th>Info</th></tr>";
                        foreach ($lists as $list){
                        $table .="<tr><td>{$list['list-host']}</td><td>{$list['list-name']}</td><td>{$list['txt-record']}</td></tr>";
                        }
                        $table .="</table>";
                        return $table;
                } else {
                        return "";
                }
        }

        /* getHtmlResumeTable:
        *       Given an IP address, its black list status, and the amount of
        *       black-lists where it is listed, it returns an html table with
        *       the headers 'IP', 'Is listed' and 'Amount'.
        *
        *  Parameters:
        *       $IP             --> SMTP IP address.
        *       $isListed       --> TRUE if the $IP is listed in any black list
        *                           that is not ignored, FALSE in other case. 
        *       $amount         --> Amount of black lists where the IP is
        *                           listed.
        *  Returns:
        *       HTML table.
        */
        function getHtmlResumeTable($IP,$isListed,$amount){
                $is_listed = 'No';
                $color = '#80FF89'; // Green
                if ($isListed){
                        $is_listed = "Si";
                        $color = '#FF6161'; // Red
                }

                return "<table border=\"1\"><tr><th>IP</th><th>Is listed</th><th>Amount</th></tr><tr>
                        <td>$IP</td><td style=\"background-color: $color\">$is_listed</td><td>$amount</td></tr></table>";
        }

        /* getHtmlResume:
        *       Given the server name, its IP address, its black-list status, 
        *       the amount of black-lists where it is listed and the list of
        *       those black-lists where the erver appears with its information.
        *       The function returns all this information in an html table.
        *
        *  Parameters:
        *       $SERVER         --> Servers FQDN (The IP is acceptable too).
        *       $IP             --> SMTP IP address.
        *       $isListed       --> TRUE if the $IP is listed in any black list
        *                           that is not ignored, FALSE in other case. 
        *       $amount         --> Amount of black lists where the IP is
        *                           listed.
        *       $lists          --> Black lists array (With its respective
        *                           information) of lists where the IP appears.
        */
        function getHtmlResume($SERVER,$IP,$isListed,$amount,$lists){
                $message = "<h3>SMTP $SERVER</h3>";
                $message .= getHtmlResumeTable($IP,$isListed,$amount);
                if ($isListed){
                        $message .= '<br/><p>Black lists:</p>';
                        $message .= getHtmlListsTable($lists);
                }
                $message .= "<br/><p>The results may not be full, visit:</p><ul>
                <li><a href=\"http://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a$IP&run=toolpage\">MXToolBox $SERVER results.</a></li>
                <li><p><a href=\"http://whatismyipaddress.com/blacklist-check\">WhatIsMyIPAddress BlackLists</a>, Ingresar IP: $IP.</p></li>
                <li><p><a href=\"http://www.dnsbl-check.info/?checkip=$IP\">DNSBL-CHECK $SERVER results.</a></p>
                <li><p><a href=\"http://www.senderbase.org/lookup/ip/?search_string=$IP\">SenderBase Cisco lookup $SERVER results.</a></p>
                <li><p><a href=\"https://ers.trendmicro.com/reputations\">Trend MICRO reputation service</a>, Ingresar IP: $IP.</p>
                </li></ul>";
                return $message;
        }

        /* sendMail:
        *       Given the administrator's name and mail, it sends the digest to
        *       the mail.
        */
        function sendMail($ADMIN_NAME, $ADMIN_MAIL, $BA_NAME, $BA_FROM, $MAIL_SUBJECT, $message){
                $headers  = 'MIME-Version: 1.0' . "\r\n";
                $headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
                $headers .= "From: $BA_NAME <$BA_FROM>\r\n";
                mail($ADMIN_MAIL, $MAIL_SUBJECT, $message, $headers);
        }

        /* get_IP:
        *       Given a server name, it returns the A record of the DNS query.
        */
        function get_IP($SERVER){
                $rta_IP = $SERVER;
                $dnsr = dns_get_record($SERVER, DNS_A);
                if ((count($dnsr)>0)&&(isset($dnsr[0]['ip']))){
                        $rta_IP = $dnsr[0]['ip'];
                }
                return $rta_IP;
        }

        /* process_theMail:
        *       Given one SMTP server (IP or FQDN), the API url, the API user
        *       and password, it returns the complte black-list state of the
        *       server in presentable HTML code.
        */
        function process_theMail($SERVER, $API_URL, $API_USER_ID, $API_KEY){
                $rta = "";
                $IP = get_IP($SERVER);
                $result_BL = get_BlackList_Result($IP, $API_URL, $API_USER_ID, $API_KEY);
                if (!isset($result_BL['error'])){
                        if (!isset($result_BL['api-error'])){
                                $black_lists = get_BlackList_array($result_BL['lists']);
                                $result_BL['list-count'] = count($black_lists);
                                if (count($black_lists) == 0){
                                        $result_BL['is-listed'] = false;
                                }
                                $rta .= getHtmlResume($SERVER,$IP,$result_BL['is-listed'],$result_BL['list-count'],$black_lists);
                        } else {
                                $rta .= "<h3>API ERROR:</h3>";
                                $rta .= "<p>Nro error = {$result_BL['api-error']}<p/><p>Menssage: {$result_BL['api-error-msg']}</p>";
                        }
                } else {
                        $rta .= "Servidor SMTP $IP. ERROR en consulta: {$result_BL['exception']}";
                }
                $rta .= '_____________________________________________________________________________________ </br>';
                return $rta;
        }
        // ----------------------------------------------------------------------------------------------------------------

        // MAIN ___________________________________________________________________________________________________________
        if (isset($SMTP_Servers)){
                $Message = "<div>";
                $amount = count($SMTP_Servers);
                for ($i=0;$i<$amount;$i++){
                        $Message .= process_theMail($SMTP_Servers[$i], $API_URL, $API_USER_ID, $API_KEY);
                        if ($i + 1 < $amount){
                                sleep($TIME_BETWEEN_API_QUERY); // Se define un tiempo minimo de ventana entre consulta.
                        }
                }
                $Message .= "</div>";
                sendMail($ADMIN_NAME, $ADMIN_MAIL, $BA_NAME, $BA_FROM, $MAIL_SUBJECT,$Message);
        }

?>
