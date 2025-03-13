Bonus Marks:
+15 git commits with clear messages (1)

# Setting Up the Repository

## Part A: Set Up Google OAuth Credentials

1. Log in to your Google Cloud Platform (GCP) account and go to the Google Cloud Console.
2. Click the Project drop-down (top-left) and select New Project.
3. Name your project and click Create.
4. Enable the Google+ API for your project.
5. In the left sidebar, select OAuth consent screen.
   a. Choose the User Type(External for most applications) and click Create.
   b. Complete the required fields (app name, support email) and click Save.
6. Go to Credentials > Create Credentials > OAuth Client ID.
   a. Select Web application as the Application type.
   b. Set the Authorized redirect URIs to http://localhost:3000/auth/google/callback
   c. Click Create.
   d. Write down the Client ID and Client Secret You’ll need these later.

## Part B: Setting Up MongoDB with Compass

1. If MongoDB is not already installed, download and install it from the MongoDB Download Centre(https://www.mongodb.com/try/download/community).
2. Launch MongoDB Compass.
3. Click New Connection and enter your MongoDB connection string (or use the default mongodb://localhost:27017 if you’re running MongoDB locally).
4. Click Connect to access the MongoDB instance.
5. Click Create Database in the left sidebar.
6. Name the database google-sso and create an initial collection called users.
   Note: You can add more collections later as needed.
7. Click Create Database.
8. In the sidebar, select google-sso to open the database.
9. If you haven’t already created the users collection, click Add Collection, name it users, and click Create Collection. This collection stores user data, including login count and role (e.g., user or super user).

## Part C: Create a New Node.js Project

1. Open a terminal or command prompt.
2. Create a new directory for your project:
   ` mkdir google-sso-example`
   `cd google-sso-example`
3. Run the following command to create a package.json file: npm init -y
4. Run the following command to install the required packages:
   `npm install express argon2 mongoose body-parser dotenv JSON web token express-session passport passport-google-oauth20 helmet connect-mongo csurf ejs https fs hsts`
5. Download the files from the repository and paste into your project folder
6. Create a .env file including:

```
   JWT_SECRET=(make up your own secret key)
   GOOGLE_CLIENT_ID=(from part A, step d)
   GOOGLE_CLIENT_SECRET=(from part A, step d)
   SESSION_SECRET=(make up your own secret key)
   DB_CONNECTION=mongodb://127.0.0.1:27017/secure-session
   PORT=3000
```

# Authentication Mechanisms

I chose Google SSO (OAuth) over local authentication because it's more convenient for users, as they don’t have to remember another set of login credentials. This results in lower customer support costs for my business, as fewer users need assistance with forgotten passwords. Additionally, by leveraging Google’s web security technology, I reduce my liability for potential hacker attacks.

Furthermore, I implemented CSRF protection to guard against unauthorized requests and used express-session to secure sessions. For JSON Web Tokens (JWT), my app stores the JWT in an HTTP-only cookie. I implemented this in routes/auth.js. Specifically, in the login route, a JWT token is generated and sent back to the client after a successful login.

# Role-Based Access Control

I have protected the user dashboard so that a person must log in to gain access; otherwise, they will receive an Error: Invalid Credentials message. I implemented two user roles: user and superuser. The app.js and middleware/auth.js files determine a user's role and forward them to their respective dashboard. A regular user attempting to access the superuser dashboard will also receive an Error: Invalid Credentials message. This ensures that sensitive information and settings can only be accessed by the appropriate role.

# Lessons Learned

There were several challenges I faced during this project:

-For local authentication, while it worked with Postman's API test, getting it to work with the web app proved to be a major challenge.

-Getting Google OAuth to work with MongoDB was also a big challenge, especially since there was a bug in the code from Lab 3. It took me a long time to troubleshoot and get it to work.

-Making the backend Node.js server communicate and work with the frontend UI web app was another significant challenge. Since we had never learned this before, I had to teach myself how to use Embedded JavaScript to create dynamic web pages for the UI.

Despite the technical difficulties, this phase of the project was a very valuable learning experience because it taught me:
-How to secure sensitive information by hashing it with Argon2
-Hands-on experience setting up and working with MongoDB to store user login info
-How to implement role-based access control to safeguard user info
-How to use various middleware to strengthen the security of the web app
-How to set up a server to work in tandem with the frontend UI
-How to set up Google OAuth SSO and understand what happens behind the scenes with SSO
-How to use various tools for session management to prevent attackers from exploiting vulnerabilities
