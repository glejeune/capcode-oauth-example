require 'rubygems'
require 'capcode'
require 'capcode/render/erb'
require 'capcode/base/dm'
require File.dirname(__FILE__) + '/lib/oauth_test_wrapper'

class Oauth < Capcode::Base
  include Capcode::Resource
 
  property :id,         Serial

  property :consumer_key,     String,  :required => true # cannot be null
  property :consumer_secret,  String,  :required => true # cannot be null

  property :request_token,    String
  property :request_secret,   String

  property :access_token,    String
  property :access_secret,   String
end

module Capcode
  set :erb, "consumer"
  before_filter :autz
  
  # --------------------------------- FILTER
  def autz
    @client ||= get_client
    rd = nil
    
    if !@client.nil?
      if @client.access_token.nil?
        @client, rd = get_access
      end
    end
    
    unless rd.nil?
      return redirect rd
    end
    return rd
  end
  
  def get_client
    oauth = Oauth.first

    if !oauth.nil?
      clientDetails = {:consumer_key => oauth.consumer_key, :consumer_secret => oauth.consumer_secret}

      if oauth.request_token and oauth.request_secret
        clientDetails.merge!({:request_token => oauth.request_token, :request_token_secret => oauth.request_secret})
      end

      if oauth.access_token and oauth.access_secret
        clientDetails.merge!({:access_token => oauth.access_token, :access_token_secret => oauth.access_secret})
      end
      
      client = OAuthTestWrapper::Client.new(clientDetails)
    end
  end

  def get_access
    oauth = Oauth.first
    
    redirect = nil

    if !oauth.access_token or !oauth.access_secret

      if !oauth.request_token or !oauth.request_secret
        request_token = @client.get_request_token
        oauth.request_token = request_token.token
        oauth.request_secret = request_token.secret
        oauth.save
      else
        begin
          access_token = @client.get_access_token

          oauth.access_token = access_token.token
          oauth.access_secret = access_token.secret
          oauth.save
        rescue
          redirect = @client.authorize_url
        end
      end

    end

    return @client, redirect
  end
  # --------------------------------- FILTER
  
  class Index < Route '/'
    def get
      render :erb => :index
    end
  end
  
  class Messages < Route '/messages/(.*)'
    def get(id = nil)
      if @client.nil?
        render :erb => :consumerkey
      else
        if @client.access_token.nil?
          redirect '/'
        else
          if id.nil?
            @messages = @client.messages
            render :erb => :list
          else
            @message = @client.show_message(id)
            render :erb => :show
          end
        end
      end
    end
    
    def post( id )
      if @client.nil?
        render :erb => :consumerkey
      else
        if @client.access_token.nil?
          redirect '/'
        else
          @message = @client.create_message(params['message_name'], params['message_details'])
          redirect "/messages/#{@message.message_id}"
        end
      end
    end
  end
  
  class AddConsumerKey < Route '/addconsumerkey'
    def post
      oauth = Oauth.new
      oauth.consumer_key = params['consumer_key']
      oauth.consumer_secret = params['consumer_secret']
      oauth.save
    
      redirect '/messages'
    end
  end
end

Capcode.run( :db_config => "consumer.yml", :port => 3001 )