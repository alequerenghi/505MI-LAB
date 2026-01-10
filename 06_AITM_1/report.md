# AITM

We setup Burp Proxy by toggling _Remove Secure flag from cookies_ and _Convert HTTPS links to HTTP_. Also we force redirect on port 443 and the use of HTTPS on the proxy listener.

<!--One other thing we can do is to add the _Match and Replace_ rule to remove the response header Upgrade-Insecure-Request: 1 -->

## Modify Selected Portions of the Response

We can inspect a web page to modify its content. For example we can look at the website `www.w3schools.com` and we can modify the content of the HTML tag to the JavaScript course to 
```HTML
<a href="http://attacker.local/malicious.exe">JAVASCRIPT</a>
```
This could be used to change the text or the link target to a potentially malicious website (attacker controlled).  
To do so we simply need to use the _HTTP Match and Replace Rule_ to add a new rule to change said link.  
This can be used for web defacement as well, even though this would not be the most impactful of techniques.

## STEAL CREDENTIALS