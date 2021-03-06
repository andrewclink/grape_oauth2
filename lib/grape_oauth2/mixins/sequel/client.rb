module Grape
  module OAuth2
    module Sequel
      # Grape::OAuth2 Client role mixin for Sequel toolkit.
      # Includes all the required API, associations, validations and callbacks.
      module Client
        extend ActiveSupport::Concern

        included do
          plugin :validation_helpers
          plugin :timestamps

          set_allowed_columns :name, :redirect_uri

          one_to_many :access_tokens, class: Grape::OAuth2.config.access_token_class_name, key: :client_id

          def before_validation
            generate_keys if new?
            super
          end

          def validate
            super
            validates_presence [:key, :secret]
            validates_unique :key
          end

          def self.authenticate(key, secret = nil)
            if secret.nil?
              find(key: key)
            else
              find(key: key, secret: secret)
            end
          end

          protected

          def generate_keys
            self.key = Grape::OAuth2::UniqueToken.generate if key.blank?
            self.secret = Grape::OAuth2::UniqueToken.generate if secret.blank?
          end
        end
      end
    end
  end
end
