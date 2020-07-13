require 'rubygems'
require 'bcrypt'
require 'sinatra'
require 'redis'
require 'securerandom'
require 'json'
require 'sinatra/config_file'
require 'sqlite3'

@@initializeDb = true

config_file 'config/config.yml'

helpers do

  def getUSer
    userEmail = redis.get(request.env['HTTP_AUTHORIZATION'])
    results = connection { |db|
      db.execute("SELECT * FROM users WHERE user_email = ?",
      [userEmail])
    }
    user = results[0]
    return {:email => userEmail,
            :id => user[0].to_s,
    }

  end

  def redis
    puts "REDIS host: #{settings.redis_host}"
    return Redis.new(host: settings.redis_host)
  end

  def connection
    initDb()
    db = SQLite3::Database.open(settings.sqlite_db_name)
    r = yield db
    db.close
    return r
  end

  def initDb
    puts "Initializind db, env:#{settings.env}:"
    if @@initializeDb
      db = SQLite3::Database.open(settings.sqlite_db_name)
      db.execute("CREATE TABLE IF NOT EXISTS
        users(user_id INTEGER PRIMARY KEY, user_email TEXT UNIQUE, password_digest TEXT)")
      if(settings.env == 'development')
        puts "setting up non prod db"

        db.execute("DELETE FROM users")

        password_hash = BCrypt::Password.create("123")
        db.execute("INSERT INTO users(user_email, password_digest) VALUES(?, ?)",
        ['abc', password_hash.to_s])
      end
      db.close
      @@initializeDb  = false;
    end
    return true
  end

  def login?
    if request.env['HTTP_AUTHORIZATION'].nil?
      return false
    else
      puts "token in request: #{request.env['HTTP_AUTHORIZATION']}"
      token = redis.get(request.env['HTTP_AUTHORIZATION'])
      puts "token nil?: #{token.nil?}"
      return !token.nil?
    end
  end
end

get "/users" do
  results = connection { |db|
    db.execute("SELECT * FROM users")
  }
  results.to_json
end

get "/signup" do
  haml :signup
end

post "/signup" do
  puts "/signup called params :#{params} -- params.to_s #{params.to_s}"
  puts params[:username] =~ URI::MailTo::EMAIL_REGEXP
  #save into database
  password_hash = BCrypt::Password.create(params[:password])
  results = connection { |db|
    db.execute("INSERT INTO users(user_email, password_digest) VALUES(?, ?)",
    [params[:userEmail], password_hash.to_s])
  }
  @message = "User created!"
  haml :index
end

post "/users" do
  body = request.body.read.to_s
  puts "POST/user invoked. params :#{body}"
  begin
      puts "1"
    params = JSON.parse(body)
      puts "2"
    userEmail =  params['userEmail'].to_s.strip
    password =  params['password'].to_s
    if userEmail.size == 0 || password.size == 0
      puts "2.1"
      raise "Bad Request."
    end
    #TODO enforce strong password policy
    #TODO VALIDATE email puts "regex? #{(params[:userEmail] =~ URI::MailTo::EMAIL_REGEXP)}"
  rescue
    halt 400, {error: 'Bad Request.'}.to_json
  end

  #save into database
  password_hash = BCrypt::Password.create(password)
  connection { |db|
    db.execute("INSERT INTO users(user_email, password_digest) VALUES(?, ?)",
    [userEmail, password_hash.to_s])
  }
  201
end

post "/login" do
  results = connection { |db|
    db.execute("SELECT password_digest FROM users WHERE user_email = ?",
    [params[:username]])
  }

  #if userTable.has_key?(params[:username])
  if results.size > 0
    restored_hash = BCrypt::Password.new results[0][0].to_s
    if restored_hash == params[:password]
      # "password match!!!"
      #Generate token
      token = SecureRandom.base64(16)

      #save token into Redis
      rd = redis
      rd.multi do
        rd.set(token, params[:username])
        rd.expire(token, 27)
      end
      halt 200, {token: token}.to_json
    end
  end
  halt 401, {error: "Incorrect user or password"}.to_json
end

get "/sum/:n" do
  if login?
    user = getUSer
    n = params['n']
    n = n.to_i
    {
      :sum => n * (n + 1) / 2,
      :userId => user[:id],
      :userEmail => user[:email]
    }.to_json
  else
    halt 403, {error: 'Access denied. You do not have authorization to view this page.'}.to_json
  end
end

__END__
@@layout
!!! 5
%html
  %head
    %title Ruby Sinatra Redis Authentication
  %body
  =yield
@@index
-if login?
  %h1= "Welcome #{username}!"
  %h3= "Your email is TBD"
  %a{:href => "/logout"} Logout
-else
  -if !@message.nil?
    %h3= @message
  %form(action="/login" method="post")

    %div
      %label(for="username")Username:
      %input#username(type="text" name="username")
    %div
      %label(for="password")Password:
      %input#password(type="password" name="password")
    %div
      %input(type="submit" value="Login")
      %input(type="reset" value="Clear")
  %p
    %a{:href => "/signup"} Signup
@@signup
%p Enter the username and password!
%form(action="/signup" method="post")
  %div
    %label(for="username")Username:
    %input#username(type="text" name="username")
  %div
    %label(for="password")Password:
    %input#password(type="password" name="password")
  %div
    %label(for="checkpassword")Password:
    %input#password(type="password" name="checkpassword")
  %div
    %input(type="submit" value="Sign Up")
    %input(type="reset" value="Clear")
@@error
%p Wrong username or password
%p Please try again!
%a{:href => "/"} Login
