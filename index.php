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

    ////////////////////////////////////////////

        // Load up the LTI 1.0 Support code
        require_once 'util/lti_util.php';
    
        var_dump($ROSTER);
    
        $encryptedSecret = LTIX::ltiParameter('secret');
        $secret = LTIX::decrypt_secret($encryptedSecret);
        $key = LTIX::ltiParameter('key_key');
    
        $oauth_consumer_secret = $secret;
        if (strlen($oauth_consumer_secret) < 1 ) $oauth_consumer_secret = 'secret';
    ?>
        <p>
            <form method="POST">
                Service URL: <input type="text" name="url" size="80" disabled="true" value="<?php echo($ROSTER->url);?>"/></br>
                lis_result_sourcedid: <input type="text" name="id" disabled="true" size="100" value="<?php echo($ROSTER->id);?>"/></br>
                OAuth Consumer Key: <input type="text" name="key" disabled="true" size="80" value="<?php echo($key);?>"/></br>
                OAuth Consumer Secret: <input type="text" name="secret" size="80" value="<?php echo($oauth_consumer_secret);?>"/></br>
            </form>
        </p>
    <?php
    
        $url = $ROSTER->url;
        $message = 'basic-lis-readmembershipsforcontext';
    
        $data = array(
          'lti_message_type' => $message,
          'id' => $ROSTER->id);
        
        $oauth_consumer_key = $key;
        
        $newdata = signParameters($data, $url, 'POST', $oauth_consumer_key, $oauth_consumer_secret);
        
        echo "<pre>\n";
        echo "Posting to URL $url \n";
        
        ksort($newdata);
        foreach($newdata as $key => $value ) {
            if (get_magic_quotes_gpc()) $value = stripslashes($value);
            print "$key=$value (".mb_detect_encoding($value).")\n";
        }
        
        global $LastOAuthBodyBaseString;
        echo "\nBase String:\n</pre><p>\n";
        echo $LastOAuthBodyBaseString;
        echo "\n</p>\n<pre>\n";
        
        $retval = do_body_request($url, "POST", http_build_query($newdata));
        
        $retval = str_replace("<","&lt;",$retval);
        $retval = str_replace(">","&gt;",$retval);
        echo "Response from server\n";
        echo $retval;
}
$OUTPUT->footer();
