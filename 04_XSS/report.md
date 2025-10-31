# XSS

## 1. EXPLOITATION ACTIVITY

### DOM XSS
The exploitation of this vulnerability in OWAS Juice Shop was quite straightforward.  
From PortSwigger's definition of DOM XSS:
> DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution

First it was necessary to find a suitable injection point.  
DOM XSS can be **most probable when there is massive use of client-side rendering**. This hints in attempting DOM XSS in the **main page where all the items are shown**.  
The most obvious place where to try was the **search bar**. The reason for this is that after looking up an item (e.g. "_apple_", "_banana_") the web **app shows the searched term on the page as a header**.  
The exploit simply consists in
```HTML
<iframe src="javascript:alert(`xss`)">
```
which was inputted in the search bar.  
After pressing enter, the search page loads, presenting a pop up window with `xss` written, and an empty `iframe` beside the _Search Result_ header:
![DOM](images/dom.png)

### Reflected XSS
The reflected XSS exploitation was less straightforward as it required to look around a bit.  
As shown in the hints, the challenge requires to **find a URL parameter which can be the source for the injection** (different to `search?q=`).  
This is found by navigating to the _Order History_ page which redirects to `/order-history`. Clicking on the **truck icon** the app navigates to the order info page with url `track-result?id=order-id`.  
Going back to the home page and setting the URL to
```
localhost:3000/track-result/<iframe%20src%3D"javascript:alert(%60xss%60)">
```
loads a page which presents a pop up window with `xss` written, and an empty `iframe` beside the _Search Result_ header:
![reflect](images/reflect.png)

## 2. UNDER THE HOOD

### Reflected XSS
The vulnerability in the application can be found looking at the source code managing the request for an order.  
Since there is no `id` in the HTML we can look directly in `main.js`; there we can find `track-result` in the code. It is referenced in a function `trackOrder` on the line 
```js
return yield o.router.navigate(['track-result']), {
```
This function is later used with a parameter named `orderId`.  
`orderId` is taken from the query URL (with `this.route.snapshot.queryParams.id`) and is assigned to a function 
```javascript
bypassSecurityTrustHtml(`<code>${e.data[0].orderId}</code>`)
```
This function is part of the **Angular framework**, from its DOM sanitizer class which is used to prevents XSS. From Angular's documentation:  
>`bypassSecurityTrustHtml`  
**Bypass security** and trust the given value to be safe HTML. Only use this when the bound HTML is unsafe and the code should be executed. The sanitizer will leave safe HTML intact, so in most situations this method should not be used.

The `orderId` is then injected, without further sanitization, into the `innerHTML` property of the element that represents the searched parameter, using the `Y8G` function.  
This code is then executed by the browser which tries to render the header.

### DOM XSS
This DOM attack is actually a reflected DOM attack.  
The searched string is URL-encoded and appended to the URL as value to the parameter `q` in the query string.  
When the page is refreshed the client code makes a request to the server with query string `q=` asking for all items. When searches are performed no request is made to the server and simply the received data is filtered.  
Looking at the HTML of the heading displaying the searched value we find that it has id `searchedValue`. In `main.js` a variable with a corresponding name is assigned its value using `bypassSecurityTrustHtml`, as before.  
Using the `Y8G` function the value of this variable is assigned to the `innerHTML` of the element representing the header in the HTML. Since no further sanitization is performed any code passed as parameter of the URL becomes part of the HTML of the page thus causing the vulnerability discussed.  
This vulnerability is definitely of DOM XSS type since the attacker is in control of the search bar.
<!-- `h2` element displaying the searched item.-->
