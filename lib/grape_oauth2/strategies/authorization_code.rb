module Grape
  module OAuth2
    module Strategies
      # Auth Code strategy class.
      # Processes request and responds with Token or Code
      # (depend on requested response type).
      class AuthorizationCode < Base
        class << self
          # Processes Authorization request.
          def process(request, response)
            client = authenticate_client(request)
            request.bad_request! if client.nil?

            puts "Got client: #{client.inspect}"
            # Request: #<Rack::OAuth2::Server::Token::AuthorizationCode::Request:0x00000003891f18>
            # Response: #<Rack::OAuth2::Server::Token::Response:0x00000003891ae0>
            
            

            # TODO: verify scopes if they valid
            # scopes = request.scope
            # request.invalid_scope! "Unknown scope: #{scope}"


            
            # resource owner can't be nil!
            access_token = config.access_token_class.create_for(client, nil, scopes_from(request))
            puts "generated access token: #{access_token}"
            token =  expose_to_bearer_token(access_token)
            puts "Generated bearer token: #{token}"
            response.access_token = token

            puts "Assigned token to response: #{response}"
            # response
            token
          end
        end
      end
    end
  end
end
