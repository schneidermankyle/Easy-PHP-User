This particular class was originally meant to be a standalone plugin to any website needing user authentication. Unfortunately many other projects took priority and this module has not had the love that it deserves. Recently I decided I would like to revitalize the project and write it better. Please keep in mind that this is in a rather rough state, there is much to be done, much coding still to be re-worked and likely many errors.

Current Features:
  •	Self-installing database
  •	Easy configuration
  •	Self-managing
  •	Supports MySql and PDO
  •	Login rate limiting

Future Plans:
  •	Omni database support
  •	Better self-installer
  •	Increased security
  •	Cleaner code
  •	More documentation
  •	Better options for error handling

Recent Changes:
  •	Added error logging

**How to install class:**

Simply include the class in your project with:

**Example:**
```HTML
Require ‘./classes/user.class.php’;
```

**How to use this class:**
As I develop this project further, I plan on adding better documentation, however until then, please bear with me. In order to configure the class just open the class file and review the $config array;

**Options:**

**•	‘db’ (optional):** if you would like the class to install and manage its own database connection you can pass in an array with your MySql database information.
```HTML
Example: ‘db’ => array(
	// Don't use root!
	'username' => 'demo',
	// And come up with a better password!
	'password' => 'password',
	// Where is your database located?
	'host' => 'localhost',
	// Your database name
	'db_name' => 'examples'
)
```

**•	'max_login_attempts':** This class supports rate limiting users to help avoid DDOS attacks.

Default Value: 5.

Optional Values: Any Integer supported by DB.

**•	'token_lengths':**  Tokens are stored both locally via $_SESSION variable as well as in the database in order to verify that requests are being requested from the proper client.

Default Value: 128.

Optional values: Any Integer supported by DB.

**•	'dbMode':** Currently this class only supports MySql databases with a PDO handler. Future plans are to support all databases

Default Value: ‘mysql’.

Optional values: None currently.

**•	'logs' (Optional):** This class supports error logging (logs information such as errors with configuration, db, and user login errors. A log directory and subsequent file will be automatically created within the directory defined within this option. If you would like logging to be turned off set this option to ‘none’

Default Value: `__DIR__`

Optional Values: ‘none’ or any other directory you have permission to write to.

**•	'mode':** Describes the current environment this class is being ran in. By default if mode is set to anything other than Development, only errors regarding user login actions will be rendered to screen.

Default Value: ‘production’

Optional Values: ‘production’, ‘development’

**•	'errorHandling':** Describes how errors should be handled. Currently error handling has one of four states: verbose, logging, silent and both. Verbose renders errors directly to the screen wherever the class is included. Logging keeps errors from rendering but logs them to the defined log instead. Silent neither logs nor renders errors but instead attempts to allow the class just figure it out. Both will both log and render errors.

Default Value: ‘log’

Optional Values: ‘verbose’, ‘log’, ‘silent’, ‘both’

**•	'authMethod':** Describes how users should be authenticated. This class supports the ability to use any column in the user database as the primary method for authentication. This allows you to have users login with things like their e-mail, username, phone number, name, etc. Please make sure that whatever you change this to, there is a corresponding column in the database. 

Default Value: ‘username’

Optional Values: ‘username’, ‘email’, ‘phone’, ‘name’, ‘id’, (custom columns defined by developer) 

Then simply instantiate your user object with:
```HTML
$user = new User($optionalPDOConnection);
```
**Functions:**
Here are a list of functions of the class
Login:
```HTML
$user->loginUser(array('username' => $_POST['username'], 'password' => $_POST['password']));
```

More on its way.
