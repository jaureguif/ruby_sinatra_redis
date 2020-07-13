require 'rubygems'
require 'bcrypt'
require 'sinatra'
require 'redis'
require 'securerandom'
require 'json'
require 'sinatra/config_file'
require 'sqlite3'

@@initializeDb = true
@@redis = nil

config_file 'config/config.yml'

helpers do

  def getUSer
    userEmail = redis.get(request.env['HTTP_AUTHORIZATION'])
    results = connection { |db|
      db.execute("SELECT * FROM users WHERE user_email = ?",
      [userEmail])
    }
    user = results[0]
    return {email: userEmail,
            id: user[0].to_s,
    }
  end

  def extract_params(body)
    begin
      json = JSON.parse(body)
      params = {
        email: json['userEmail'].to_s.strip,
        password: json['password'].to_s
      }
      yield params if block_given?
      #TODO enforce strong password policy
      #TODO VALIDATE email puts "regex? #{(params[:userEmail] =~ URI::MailTo::EMAIL_REGEXP)}"
    rescue => e
      puts "rescued! #{e}"
      halt 400, {error: 'Bad Request.'}.to_json
    end
    return params
  end

  def crypt(password)
    return BCrypt::Password.create(password).to_s
  end

  def redis
    if @@redis.nil?
      return Redis.new(host: settings.redis_host)
    else
      return @@redis
    end
  end

  def connection
    begin
      initDb()
      db = SQLite3::Database.open(settings.sqlite_db_name)
      r = yield db
      db.close
      return r
    rescue => e
      puts "Rescued! #{e}"
      halt 500, {error: "#{e}"}.to_json
    end
  end

  def insertUserStmnt(db)
    return db.prepare(<<-EOS)
      INSERT INTO users(user_email, password_digest)
      VALUES(:email, :hash)
    EOS
  end

  def initDb
    puts "Initializind db, env:#{settings.env} db name:#{settings.sqlite_db_name}"
    if @@initializeDb
      db = SQLite3::Database.new(settings.sqlite_db_name)
      db.execute(<<-EOS)
        CREATE TABLE IF NOT EXISTS users (
          user_id INTEGER PRIMARY KEY,
          user_email TEXT UNIQUE NOT NULL,
          password_digest TEXT NOT NULL)
      EOS

      #execute further settings depending on the environment to deployed
      case settings.env

      when 'development'
        puts "setting up dev db"
        #delete all previous records
        db.execute("DELETE FROM users")
        stmt = insertUserStmnt(db)
        stmt.execute( email: 'abc@wiggot.com',
                      hash: crypt("123"))
        stmt.close

      when 'test'
        # test db setup goes here
        puts "setting up test db"

      when 'production'
        # PROD db setup goes here
        puts "setting up prod db"
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
      authHeader = request.env['HTTP_AUTHORIZATION']
      puts "token in request: #{authHeader}"
      if authHeader["Bearer"]
        authHeader[0,7] = ""
        puts "trimmed token:#{authHeader}"
      end
      token = redis.get(authHeader)
      puts "token nil?: #{token.nil?}"
      return !token.nil?
    end
  end
end

get "/users" do
  # for debug purposes only,
  # maybe for an admin role would work,
  # after implementing authorization on top of authentication
  results = connection { |db|
    db.execute("SELECT * FROM users")
  }
  results.to_json
end

post "/users" do
  body = request.body.read.to_s
  puts "POST/user invoked. params :#{body}"

  params = extract_params(body){ |params|
    if params[:email].size == 0 || params[:password].size == 0
      raise "Bad Request."
    end
  }
  #save into database
  connection { |db|
    stmt = insertUserStmnt(db)
    stmt.execute(email: params[:email], hash: crypt(params[:password]))
    stmt.close
  }
  201
end

post "/login" do
  body = request.body.read.to_s
  puts "POST/user invoked. params :#{body}"
  params = extract_params(body)
  puts params
  results = connection { |db|
    db.execute("SELECT password_digest FROM users WHERE user_email = ?", params[:email])
  }

  #if userTable.has_key?(params[:username])
  if results.size > 0
    puts "101 results #{results}"
    restored_hash = BCrypt::Password.new results[0][0].to_s
    puts "restored #{restored_hash}, pas #{params[:password]}"
    if restored_hash == params[:password].to_s
      puts "102"
      # "password match!!!"
      #Generate token
      token = SecureRandom.base64(16)

      #save token into Redis
      rd = redis
      rd.multi do
        rd.set(token, params[:email])
        rd.expire(token, (settings.token_expiration_minutes.to_f * 60).to_i)
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
      sum: n * (n + 1) / 2,
      userId: user[:id],
      userEmail: user[:email]
    }.to_json
  else
    halt 403, {error: 'Access denied. You do not have authorization to view this page.'}.to_json
  end
end
