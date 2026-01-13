# AITM

## SETUP

To setup Burp Proxy to perform SSLSTRIP attacks I performed the following actions:
* Force the use of TLS on the proxy listener by modifying the interface
* Toggle _Remove Secure flag from cookies_ 
* Toggle _Convert HTTPS links to HTTP_
* Add a replace rule to remove _Strict-Transport-Security_ response header
* Add a replace rule to remove _Content-Security-Policy_ response header

<!--One other thing we can do is to add the _Match and Replace_ rule to remove the response header Upgrade-Insecure-Request: 1 -->

## CTAN.ORG

Ctan, the Comprehensive TeX Archive Network is the main archive for TeX packages. It contains packages and documentation, as well as wikis and infos about TeX.  
It doesn't contain HSTS response headers.

### Modify Selected Portions of the Response

Using match and replace rules we can change the header to
```HTML
<h1 style="color:red">⚠ Website Compromised ⚠</h1> 
```
which results in:
![Header modified](images/header.png)

### Steal Credentials

Credentials can be stolen by simply looking at post requests for `ctan.org/k_spring_security_check` and can be extracted from the request body.

### JavaScript Injection

Using match and replace rules we can add a script to the page using
```HTML
<script> alert("MITM active: traffic intercepted"); </script></body>
```
which results in
![alert](images/alert.png)
We note that more complex scripts could be added to perform other actions, such as reading and modifying cookies, modifying programmatically other parts of the page and so on.

### Cookies Manipulation
We can extract the cookie from the request and store it to perform Session Hijacking.

To do so we open the developer tools and in the Storage session add the relevant cookie. The cookie can be sent to the attacker to perform session hijacking by simply visiting the same site and adding the cookie.

### Download Link Manipulation

Links to download packages can be manipulated to perform Supply Chain Compromise or Integrity Compromise.  
A match and replace rule can be introduced to modify the download URL like:
```HTML
<a href="http://lab.local/payloads/fake_update.txt">Download</a> 
```
which will attempt to download malicious packages.

## INTESASANPAOLO.COM

### Without HSTS

If the page is loaded before loading `Strict-Transport-Security` then the browser doesn't present any warning and modifications can be performed as in the previous case, for instance we can replace an element with:
```HTML
<a href="/it/persone-e-famiglie.html" class="active" id="vtdd24bddcae08cd92a7a19736df002e2e60bdc2ddfd81f525b3b8dda43a185470" style="color:red; text:bold">Website Compromised</a>
```
which results in:

![sanpaolo compromised](images/compromised.png)

### With HSTS

After connecting securely with HTTPS (while not connected to the proxy) the browser successfully loads the `Strict-Transport-Security` headers.  
This can be verified when visiting the website on HTTP while connecting to the proxy:
![hsts](images/hsts.png)
Navigation is prevented and cannot be circumvented by applying an exception rule to the browser.