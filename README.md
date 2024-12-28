Authentication and Authorization using .NET Core 8 WbeAPIs,

**What does this Service do?**
- Authenticate: Create users, Login, Reset Password, and Verify created accounts.
- Authorized: By validating the issued JWT Tokens with Claims (User, Editor, Admin)
- Data Store: Data saved using SQL Server,

**TechStack**:
- Automapper: Used to abstract the DB Models from the front-end "user" request.
- JWT Tokens and Claims: Used to authorize and protect sensitive endpoints.
- Swagger: Endpoint API Explorer
- Entity Framework, Data First approach using DbContext.
- Middleware for Logging and Global Exception Handling.

**Assumptions:**
- Users Create a new account, using a "unique" and valid Email Address, and user name
- After account creation, the user will receive a unique temp code, to validate his email
- once the user account is activated, users can log, in and be granted a Token (valid for 20 minutes or 28 days)
- 28 days tokens are generated if the "Remember Me" option is enabled
- Users with unactivated emails, can not reset passwords.
- Admin Only End-point, which can be accessed via "Admin" only Users,
- Users and Editor's End-point, can be accessed by Admins.
- The attached Postman collection covers all endpoints.

**Example Screenshots:**
![image](https://github.com/user-attachments/assets/92b60243-54ad-4efc-a939-d11c8de67140)

![image](https://github.com/user-attachments/assets/181b0d2b-d059-4abd-a3dd-9d5444259fea)

Success Generated JWT Token:
![image](https://github.com/user-attachments/assets/abae1b48-017c-4c82-b942-b280a2c4bfba)

Example of exceptions handled via _ExceptionMiddleware_
![image](https://github.com/user-attachments/assets/ea79b051-1589-453a-af4c-8feb822d61d7)