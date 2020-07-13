# README

## Wiggot Sample Application

* This POC (Proof Of Concept) application was created using *Ruby* languaje, *Sinatra* Framework, *Redis* as session manager and *SQLite3*, as the database to persist user data, in this particular case, the login credentials
The application has the following endpoints:

  * **POST/users**<br></br>
Creates a new User and stores it in the database, the password is encrypted in the database, anyone can use this endpoint, as a singup service, but it can be easily restricted to authenticated users.
    <br></br>cUrl example:
    > curl -X POST -H "Content-Type: application/json" -d "{\"userEmail\":\"user@wiggot.com\",\"password\":\"supersecret\"}" localhost:4567/users

  * **POST/login**<br></br>
 Verifies that the provided params match the given user and return a token the is added to Redis with an expiration time configured in the config file.
 If credentials do not match app will return a 401 status code, if a param is missing, you will get a 400, bad request, status code.
    <br></br>cUrl example:
    > curl -X POST -H "Content-Type: application/json" -d "{\"userEmail\":\"user@wiggot.com\",\"password\":\"supersecret\"}" localhost:4567/login

  * **GET/sum/{n}**<br></br>
 Will calculate the sum of numbers from 1 to {n}, it will also retrieve the user information from database based on the active token stored in Redis, thus, the endpoint result will be conformed of
    * *sum*, the sum of numbers from 1, to n
    * *userId*, the user id
    * *userEmail*, the stored user email, also used as a user identifier in login

    #### Note:
    You must be loged in and have a valid, active token and send it as an Authorization header.
    <br></br>cUrl example:
    > curl -H "Authorization: <<VALID_TOKEN>>" -H "Content-Type: application/json" localhost:4567/sum/100

  * **GET/users**<br></br>
 This endpoint will print all users info in database.
For debug purposes only, maybe for an admin role would work, after implementing authorization on top of authentication.
    <br></br>cUrl example:
    > curl localhost:4567/users


* Configuration
Config parameters can be setup in /config/config.yml

* Database creation
Database will be created the first time a call needs it (lazy initialize design patter)

* Database initialization
Install and run the latest version of [sqlite3](https://www.sqlite.org/)

* Redis initialization
Install and run the latest version of [Redis](https://redis.io/)

* How to run the app
The application can hold configuration for different environments, for this demo, redis is always running in localhost, but can be changed in the config.yml file, a db file will be created for one of each environment:
  * dev.db for development
  * tes.db for test env
  * prod.db for production

1. Install required gems in Gemfile via Bundle or cli
2. Set the environment variable according to your OS, eg, in windows:
> set APP_ENV=production

3. Now run the app with the following command:
  >ruby wiggotSampleApp.rb
