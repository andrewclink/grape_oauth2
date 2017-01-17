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
            
            puts request.response_type

            # TODO: verify scopes if they valid
            # scopes = request.scope
            # request.invalid_scope! "Unknown scope: #{scope}"

            case request.response_type
            when :code
              raise "No, this code is not dead" # Please comment as to what caused this code to run

              # Verify Redirect
              response.redirect_uri = request.verify_redirect_uri!(client.redirect_uri)

              # resource owner can't be nil!
              authorization_code = config.access_grant_class.create_for(client, nil, response.redirect_uri)
              response.code = authorization_code.token

              response.approve!
            when :token
              
              # Verify Redirect
              
              
              # resource owner can't be nil!
              access_token = config.access_token_class.create_for(client, nil, scopes_from(request))
              response.access_token = expose_to_bearer_token(access_token)
            end

            response
          end
        end
      end
    end
  end
end
