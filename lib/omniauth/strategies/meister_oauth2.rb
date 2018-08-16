require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class MeisterOauth2 < OmniAuth::Strategies::OAuth2

      option :name, 'meister_oauth2'

      option :client_options, {
               site: "https://www.mindmeister.com",
               authorize_url: "https://www.mindmeister.com/oauth2/authorize",
               token_url: "https://www.mindmeister.com/oauth2/token"
             }

      uid { raw_info["id"] }

      info do
        # raw_info.merge(token: access_token.token)
        {
          name: raw_info['name'],
          email: raw_info['email']
        }
      end

      extra do
        { raw_info: raw_info }
      end
            
      def raw_info
        @raw_info ||= access_token.get('https://www.mindmeister.com/api/v2/users/me').parsed
      end

      def request_phase
        super
      end

      def callback_phase
        super
      end
    end
  end
end
