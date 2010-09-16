require 'rubygems'

require 'capcode'
require 'capcode/render/erb'
require 'capcode/base/dm'

require 'oauth'
require 'oauth/server'
require 'oauth/signature'
require 'oauth/request_proxy/rack_request'

require 'dm-serializer'

# -- FIX ----------------------------------------------------------------------
# Extend OAuth::Token to be able to create the correct query string form
module OAuth
  class Token
    def to_query
      "oauth_token=#{escape(token)}&oauth_token_secret=#{escape(secret)}"
    end
  end
end

# -- MODEL --------------------------------------------------------------------

class User < Capcode::Base
  include Capcode::Resource
  property :id, Serial
  
  property :mail, String, :unique => true, :required => true
  property :realname, String, :required => true
  property :password_hash, String
  property :password_salt, String
  
  has n, :messages
  has n, :consumers
  
  has n, :user_requests
  has n, :user_accesses
  
  def password=(pass)
    salt = [Array.new(6){rand(256).chr}.join].pack("m").chomp
    self.password_salt, self.password_hash = salt, Digest::SHA256.hexdigest( pass + salt )
  end

  def self.authenticate( mail, password )
    user = User.first( :mail => mail )
    if user.blank? || Digest::SHA256.hexdigest( password + user.password_salt ) != user.password_hash
      return nil
    end
    return user
  end
end

class Message < Capcode::Base
  include Capcode::Resource
 
  property :id, Serial    # primary serial key
  property :name, String, :required => true # cannot be null
  property :details, Text, :required => true # cannot be null

  property :created_at, DateTime
  property :updated_at, DateTime
  
  belongs_to :user
end

class UserAccess < Capcode::Base
  include Capcode::Resource

  property :id, Serial
  property :request_shared_key, String, :required => true
  property :shared_key, String, :unique => true, :required => true
  property :secret_key, String, :unique => true, :required => true

  belongs_to :consumer
  belongs_to :user
end

class UserRequest < Capcode::Base
  include Capcode::Resource

  property :id, Serial
  property :user_id, Integer
  property :authorized, Boolean, :default => false, :required => true
  property :shared_key, String, :unique => true, :required => true
  property :secret_key, String, :unique => true, :required => true

  def authorize( user )
    self.authorized = true
    self.user = user
    self.save
  end

  belongs_to :consumer
  belongs_to :user
end

class Consumer < Capcode::Base
  include Capcode::Resource

  property :id, Serial
  property :name, String
  property :callback, String
  property :shared_key, String, :unique => true, :required => true
  property :secret_key, String, :unique => true, :required => true

  has n, :user_requests
  has n, :user_accesses
  
  belongs_to :user
end

# -- REQUIRED CLASSES ---------------------------------------------------------

class OAuthProvider
  class Token
    def self.generate
      new(generate_key(16), generate_key)
    end

    def self.generate_key(size = 32)
      Base64.encode64(OpenSSL::Random.random_bytes(size)).gsub(/\W/,'')
    end

    def initialize(shared_key, secret_key)
      @shared_key, @secret_key = shared_key, secret_key
    end
    attr_reader :shared_key, :secret_key

    def query_string
      OAuth::Token.new(shared_key, secret_key).to_query
    end

    def ==(token)
      return false unless token.is_a?(Token)
      [shared_key, secret_key].eql?([token.shared_key, token.secret_key])
    end
  end
  
  # -- Customer --
  
  def add_consumer( user, name, callback = '' )
    token = Token.generate  
    model = Consumer.new(
      :name => name,
      :callback => callback,
      :shared_key => token.shared_key,
      :secret_key => token.secret_key,
      :user => user
    )
    model.save || raise("Failed to create Consumer: #{model.inspect}, #{model.errors.inspect}")
    model
  end
  
  def destroy_consumer( user, shared_key )
    consumer = Consumer.first(:shared_key => shared_key, :user => user)
    consumer && consumer.destroy
  end
  
  def consumers(user)
    Consumer.all(:user => user)
  end

  def find_consumer(shared_key)
    Consumer.first(:shared_key => shared_key)
  end
  
  # -- User --
  
  def find_user_request(oauth_token)
    UserRequest.first(:shared_key => oauth_token)
  end
  
  def find_user_access(oauth_token)
    UserAccess.first(:shared_key => oauth_token)
  end
  
  # -- Request verification --
  
  def issue_request(request)
    consumer = nil
    signature = OAuth::Signature.build(request) do |shared_key,consumer_shared_key|
      consumer = find_consumer(consumer_shared_key)
      [nil, consumer.secret_key]
    end
    
    unless signature.verify
      raise "Signature verification failed: #{signature.signature} != #{signature.request.signature}"
    end
    
    token = Token.generate
    authorized = false
    
    consumer.user_requests.create(
      :shared_key => token.shared_key,
      :secret_key => token.secret_key,
      :authorized => authorized
    )
    
    token
  end
  
  def upgrade_request(request)
    user_request = nil
    signature = OAuth::Signature.build(request) do |shared_key,consumer_shared_key|
      consumer = find_consumer(consumer_shared_key)
      user_request = consumer.user_requests.first( :shared_key => shared_key )
      [user_request.secret_key, consumer.secret_key]
    end
    
    unless signature.verify
      raise "Signature verification failed: #{signature.signature} != #{signature.request.signature}"
    end
    
    token = nil
    if user_request.authorized
      token = Token.generate
      
      # CREATE USER ACCESS
      user_request.consumer.user_accesses.create(
        :request_shared_key => user_request.shared_key,
        :shared_key => token.shared_key,
        :secret_key => token.secret_key,
        :user => user_request.user
      )
      
      # DESTROY USER REQUEST
      user_request.destroy
    end
    
    token
  end
  
  def confirm_access(request)
    user_access = nil

    signature = OAuth::Signature.build(request) do |shared_key,consumer_shared_key|
      consumer = find_consumer(consumer_shared_key)
      user_access = consumer.user_accesses.first( :shared_key => shared_key )
      [user_access.secret_key, consumer.secret_key]
    end
    
    unless signature.verify
      raise "Signature verification failed: #{signature.signature} != #{signature.request.signature}"
    end
    
    token = nil
    if user_access
      token = Token.new( user_access.shared_key, user_access.secret_key )
    end
    
    token
  end
end

# -- WEBSITE ------------------------------------------------------------------

PROVIDER = OAuthProvider.new()

module Capcode
  set :erb, "provider2"
  
  # -- Filters --
  
  before_filter :check_login
  def check_login
    if session[:user]
      @user = User.get(session[:user])
      if @user.nil?
        @login = "Login"
        session.delete(:user)
      else
        @login = "Logout #{@user.realname}"
        session.delete(:redirect) if session[:redirect]
      end
    else
      @user = nil
      @login = "Login"
    end
    nil
  end
  
  before_filter :user_logged, :only => [:Messages, :OAuthApplications, :OAuthAppDelete, :Connections, :ConnectionsDelete, :OAuthAuthorize]
  def user_logged
    if @user.nil?
      session[:redirect] = env['REQUEST_URI']
      redirect '/login'
    else
      nil
    end
  end
  
  before_filter :protected_path, :only => [:OAuthMessages, :OAuthMessagesID]
  def protected_path
    @user_access_token = PROVIDER.confirm_access(request)
    if @user_access_token.nil?
      return "No access! Please verify your OAuth access token and secret."
    end
    
    @user = UserAccess.first( :shared_key => @user_access_token.shared_key ).user
    return nil
  end
  
  # -- Website --
  
  class Index < Route "/"
    def get
      redirect "/messages"
    end
  end
  
  class Login < Route "/login"
    def get
      if @user.nil?
        render :erb => :login
      else
        session.delete(:user)
        redirect Index
      end
    end
    
    def post
      if params['user_signup']
        user = User.new( 
          :mail => params['user_mail'],
          :realname => params['user_name']
        )
        user.password = params['user_password']
        if user.save 
          @message = "Account created! Please login."
        else
          @message = "Account creation failed! Please try again."
        end
        render :erb => :login
      else
        user = User.authenticate( params['user_mail'], params['user_password'] )
        if user
          session[:user] = user.id
          redirect session[:redirect] || Index
        else
          @message = "Login failed! Please try again."
          render :erb => :login
        end
      end
    end
  end
  
  class Messages < Route "/messages", "/show/(.*)"
    def get( id = nil )
      if id.nil?
        @messages = @user.messages.all( :order => [:updated_at.desc])
        render :erb => :list
      else
        @message = Message.get(id)
        if @message
          render :erb => :show
        else
          redirect '/messages'
        end
      end
    end
    
    def post(id = nil)
      @message = Message.new(
        :name => params['message_name'], 
        :details => params['message_details'],
        :created_at => Time.now(),
        :updated_at => Time.now()
      )
      @message.user = @user
      if @message.save
        redirect "/show/#{@message.id}"
      else
        redirect '/messages'
      end
    end
  end
  
  # -- Gestion des applications --
  
  class OAuthApplications < Route "/oauth/applications"
    def get
      @consumers = PROVIDER.consumers(@user)
      render :erb => :applications
    end
    
    def post
      begin
        @consumer = PROVIDER.add_consumer(@user, params['application_name'], params['application_callback'])
        
        @consumer_key = @consumer.shared_key
        @consumer_secret = @consumer.secret_key
      rescue Exception => e
        @error = "Failed to create a token!<br /><b>#{e.to_s}</b>"
      end

      @consumers = PROVIDER.consumers(@user)

      render :erb => :applications
    end
  end
  
  class OAuthAppDelete < Route "/oauth/delete/(.*)"
    def get( shared_key )
      PROVIDER.destroy_consumer(@user, shared_key)
      redirect '/oauth/applications'
    end
  end
  
  # -- Gestion des connexions --
  
  class Connections < Route "/connections"
    def get
      @consumers = @user.user_accesses.consumer
      render :erb => :connections
    end
  end
  
  class ConnectionsDelete < Route "/connection/delete/(.*)"
    def get(token)
      
      redirect '/'
    end
  end
  
  # -- OAuth --
  class OAuthRequestToken < Route "/oauth/request_token"
    def get
      PROVIDER.issue_request(request).query_string
    end
  end
  
  class OAuthAuthorize < Route "/oauth/authorize"
    def get
      if @user_request = PROVIDER.find_user_request(params['oauth_token'])
        render :erb => :authorize
      else
        raise "No such request token"
      end
    end
    
    def post
      if @user_request = PROVIDER.find_user_request(params['oauth_token'])
        if params['authorize'] == "yes"
          if @user_request.authorize( @user )
            redirect @user_request.consumer.callback
          else
            raise "Could not authorize"
          end
        else
          render :erb => :not_authorize
        end
      else
        raise "No such request token"
      end
    end
  end

  class OAuthAccessToken < Route "/oauth/access_token"
    def get
      def get
        begin
          if access_token = PROVIDER.upgrade_request(request)
            access_token.query_string
          else
            raise "No such request token"
          end
        rescue
          raise "C'EST LA QUE CA MERDE !!!"
        end
      end
    end
  end
    
  # -- APIs --
  
  class OAuthMessages < Route '/messages.json'
    def get
      @user.messages.to_json
    end
    
    def post
      def post
      	record = Message.new(JSON.parse(CGI::unescape(request.body.read.to_s))["message"])
      	record.created_at = Time.now()
        record.updated_at = Time.now()
        record.user = @user
      	record.save
      	record.to_json
      end
    end
  end
  
  class OAuthMessagesID < Route '/message/(.*).json'
    def get( id )
      @user.messages.get(id).to_json
    end
  end
end

Capcode.run( :db_config => "provider2.yml" )