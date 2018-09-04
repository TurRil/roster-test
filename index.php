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

$handledRoster = LTIX::populateRoster(false, false);

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

    echo "<pre>\n";
    var_dump($ROSTER);
    echo "</pre>\n";

    $id = $ROSTER->id;
    $url = $ROSTER->url;
    $encryptedSecret = LTIX::ltiParameter('secret');
    $secret = LTIX::decrypt_secret($encryptedSecret);
    $key_key = LTIX::ltiParameter('key_key');

    $content_type = "application/x-www-form-urlencoded";
    $id = htmlspecialchars($id);

    $messagetype = LTIConstants::LTI_MESSAGE_TYPE_CONTEXTMEMBERSHIPS;

    $parameters = array(
        LTIConstants::EXT_CONTEXT_REQUEST_ID => $id,
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

    $acc_req = OAuthRequest::from_consumer_and_token($test_consumer, $test_token, "POST", $url, $parameters);
    $acc_req->sign_request($hmac_method, $test_consumer, $test_token);

    $header = $acc_req->to_header();
    $header .= PHP_EOL . "Content-Type: " . $content_type . PHP_EOL;

    $response = Net::doBody($url, "POST", $body, $header);

    $response = str_replace("<","&lt;",$response);
    $response = str_replace(">","&gt;",$response);
    echo "Response from server\n";

    echo "<pre>\n";
    var_dump($header);
    echo "</pre>";

    echo "<pre>\n";

        $b = explode('&',$body);
        foreach($b as $key => $value ) {
           if (get_magic_quotes_gpc()) $value = stripslashes($value);
            print "$key=$value (".mb_detect_encoding($value).")\n";
        }

    echo "</pre>";

    echo "<pre>\n";
    echo $response;
    echo "</pre>\n";


    ////////////////////////////////////////////

        // Load up the LTI 1.0 Support code
        require_once 'util/lti_util.php';

        var_dump($ROSTER);
    ?>
        <p>
            <form method="POST">
                Service URL: <?php echo($url);?></br>
                lis_result_sourcedid: <?php echo($id);?></br>
                OAuth Consumer Key: <?php echo($key_key);?></br>
                OAuth Consumer Secret: <?php echo($secret);?></br>
            </form>
        </p>
    <?php

        $data = array(
          'lti_message_type' => $messagetype,
          'id' => $id);

        $newdata = signParameters($data, $url, 'POST', $key_key, $secret);
        $ndata = LTI::signParameters($data, $url, 'Post', $key_key, $secret);

	//$ndata->set_parameter(LTIConstants::EXT_CONTEXT_REQUEST_ID, $id);
        //$ndata->set_parameter(LTIConstants::LTI_MESSAGE_TYPE, $messagetype);
        //$ndata->set_parameter(LTIConstants::LTI_VERSION, LTIConstants::LTI_VERSION_1);

        //$param = array_merge( $ndata->get_parameters(), array(
	//   'oauth_callback' => 'about:blank'
        //));

	$param = $ndata; //explode('&', $ndata->get_signable_parameters());

        echo "<pre>\n";
        echo "Posting to URL $url \n";

        ksort($newdata);
        foreach($newdata as $key => $value ) {
            if (get_magic_quotes_gpc()) $value = stripslashes($value);
            print "$key=$value (".mb_detect_encoding($value).")\n";
        }
	echo "----\n";
        ksort($param);
        foreach($param as $key => $value ) {
            if (get_magic_quotes_gpc()) $value = stripslashes($value);
            print "$key=$value (".mb_detect_encoding($value).")\n";
        }

	//var_dump($ndata->get_signable_parameters());
        echo "</pre>";

	//$retval = do_body_request($url, "POST", http_build_query($newdata)); //http_build_query($param)
	$retval = Net::doBody($url, "POST", http_build_query($ndata), "Content-Type: application/x-www-form-urlencoded"); //$body, $header);

        $retval = str_replace("<","&lt;",$retval);
        $retval = str_replace(">","&gt;",$retval);

	echo "<pre>\n";
        echo "Response from server\n";
        echo $retval;
	echo "<\pre>";

}
$OUTPUT->footer();
