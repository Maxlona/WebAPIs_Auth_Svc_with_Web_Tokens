Authentication and Authorization using .NET Core 8 WbeAPIs,

**What does this Service do?**
- _Authenticate_: Create users, Login, Issue JWT Access Tokens, Reset Password, and Verify Access.
- _Authorized_: By validating the issued JWT Tokens with Claims (User, Editor, Admin).

**Tech Stack**:
- Automapper: Used to abstract the DB Models from the front-end "user" request.
- JWT Tokens and Claims: Used to authorize and protect sensitive endpoints.
- Swagger: Endpoint API Explorer
- Entity Framework: Code First approach & DbContext (SQL Tables included).
- Middleware for Logging and Global Exception Handling.

**Assumptions:**
- Users Create a new account, using a "unique" and valid Email Address, and user name
- After account creation, the user will receive a unique temp code, to validate his email
- once the user account is activated, users can log, in and be granted a Token (valid for 20 minutes or 28 days)
- 28 days tokens are generated if the "Remember Me" option is enabled
- Users with unactivated emails, can not reset passwords.
- Admin Only End-point, which can be accessed via "Admin" only Users,
- Users and Editor's End-point, can be accessed by Admins.
- To reset users' passwords, users will "Request" password reset, using the generated temp code, to change the password. 
- The attached Postman collection covers all endpoints.
- Refresh Token: Used to issue a new token, from an expired JWT Token... valid for 3 minutes.

**Example Screenshots:**

![image](https://github.com/user-attachments/assets/26c5d8d5-02f2-4f97-93c3-4016eaec748e)

![image](https://github.com/user-attachments/assets/181b0d2b-d059-4abd-a3dd-9d5444259fea)

Postman test login Successfully Generated JWT Token
![image](https://github.com/user-attachments/assets/abae1b48-017c-4c82-b942-b280a2c4bfba)

https://jwt.io/ 
![image](https://github.com/user-attachments/assets/5b0c3226-1aac-44d5-a0c1-098e7ec62990)



Example of exceptions handled via _ExceptionMiddleware_
![image](https://github.com/user-attachments/assets/ea79b051-1589-453a-af4c-8feb822d61d7)
