<?php
require_once "../config.php";

// The Tsugi PHP API Documentation is available at:
// http://do1.dr-chuck.com/tsugi/phpdoc/

use \Tsugi\Core\LTIX;
use \Tsugi\Core\Settings;
use \Tsugi\Util\Net;

use \Tsugi\Util\LTI;
use \Tsugi\Util\LTIConstants;
use \Tsugi\OAuth\TrivialOAuthDataStore;
use \Tsugi\OAuth\OAuthServer;
use \Tsugi\OAuth\OAuthSignatureMethod_HMAC_SHA1;
use \Tsugi\OAuth\OAuthSignatureMethod_HMAC_SHA256;
use \Tsugi\OAuth\OAuthRequest;
use \Tsugi\OAuth\OAuthConsumer;
use \Tsugi\OAuth\OAuthUtil;

use \Tsugi\Util\Mimeparse;

// No parameter means we require CONTEXT, USER, and LINK
$LAUNCH = LTIX::requireData();

$handledRoster = LTIX::populateRoster(true);

error_reporting(E_ALL & ~E_NOTICE);
ini_set("display_errors", 1);

// Render view
$OUTPUT->header();
$OUTPUT->bodyStart();
$OUTPUT->topNav();
$OUTPUT->welcomeUserCourse();
$OUTPUT->flashMessages();

// Prepare for view
if ( $USER->instructor ) {
    echo("<p>handledRoster: ". ($handledRoster?"T":"F") ."</p>");

    $encryptedSecret = LTIX::ltiParameter('secret');
    $secret = LTIX::decrypt_secret($encryptedSecret);
    $key_key = LTIX::ltiParameter('key_key');
    $membershipsurl = $ROSTER->url;
    $membershipsid = $ROSTER->id;

    $content_type = "application/x-www-form-urlencoded";
    $membershipsid = htmlspecialchars($membershipsid);

    $messagetype = LTIConstants::LTI_MESSAGE_TYPE_CONTEXTMEMBERSHIPS;

    $parameters = array(
        LTIConstants::EXT_CONTEXT_REQUEST_ID => $membershipsid,
        LTIConstants::LTI_MESSAGE_TYPE => $messagetype,
        LTIConstants::LTI_VERSION => LTIConstants::LTI_VERSION_1
    );

    $body = http_build_query($parameters, null,"&", PHP_QUERY_RFC3986);
    $hmac_method = new OAuthSignatureMethod_HMAC_SHA1();
    $hash = base64_encode(sha1($body, TRUE));
    if ( $signature == "HMAC-SHA256" ) {
        $hmac_method = new OAuthSignatureMethod_HMAC_SHA256();
        $hash = base64_encode(hash('sha256', $body, TRUE));
    }
    $parameters['oauth_body_hash'] = $hash;

    $test_token = '';

    $test_consumer = new OAuthConsumer($key_key, $secret, NULL);

    $acc_req = OAuthRequest::from_consumer_and_token($test_consumer, $test_token, "POST", $membershipsurl, $parameters);
    $acc_req->sign_request($hmac_method, $test_consumer, $test_token);

    $header = $acc_req->to_header();
    $header .= PHP_EOL . "Content-Type: " . $content_type . PHP_EOL;

    $response = Net::doBody($membershipsurl, "POST", $body,$header);

    $response = str_replace("<","&lt;",$response);
    $response = str_replace(">","&gt;",$response);
    echo "Response from server\n";

    echo "<pre>\n";
    echo $response;
    echo "</pre>\n";
}
$OUTPUT->footer();
