<?php
// Connection 
$DATABASE_HOST = 'sql202.epizy.com';
$DATABASE_USER = 'epiz_33411201';
$DATABASE_PASS = '';
$DATABASE_NAME = 'epiz_33411201_login';
// Try and connect using the info above.
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if (mysqli_connect_errno()) {
	// Internet broke again
	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}
// User broke again
if (!isset($_POST['username'], $_POST['password'], $_POST['email'])) {
	// Could not get the data that should have been sent.
	exit('Please complete the registration form!');
}
// User also broke
if (empty($_POST['username']) || empty($_POST['password']) || empty($_POST['email'])) {
	// One or more values are empty.
	exit('Please complete the registration form');
}
//input filtering:
if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
	exit('Email is not valid!');
}
if (preg_match('/^[a-zA-Z0-9]+$/', $_POST['username']) == 0) {
    exit('Username is not valid!');
}
if (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5) {
	exit('Password must be between 5 and 20 characters long!');
}
if ($stmt = $con->prepare('SELECT id, password FROM accounts WHERE username = ?')) {
	// Bind parameters (s = string, i = int, b = blob, etc), hash the password using the PHP password_hash function.
	$stmt->bind_param('s', $_POST['username']);
	$stmt->execute();
	$stmt->store_result();
	// Store the result so we can check if the account exists in the database.
	if ($stmt->num_rows > 0) {
		// Username already exists
		echo 'Username exists, please choose another!';
	} else {
		if ($stmt = $con->prepare('INSERT INTO accounts (username, password, email) VALUES (?, ?, ?)')) {
    	// We do not want to expose passwords in our database, so hash the password and use password_verify when a user logs in.
    	$password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    	$stmt->bind_param('sss', $_POST['username'], $password, $_POST['email']);
    	$stmt->execute();
    	echo 'You have successfully registered! You can now login!';
    } else {
    	// Something is wrong with the SQL statement, so you must check to make sure your accounts table exists with all 3 fields.
    	echo 'Could not prepare statement!';
    }
	}
	$stmt->close();
} else {
	// Something is wrong with the SQL statement, so you must check to make sure your accounts table exists with all 3 fields.
	echo 'Could not prepare statement!';
}
$con->close();
?>