require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class MeisterOauth2 < OmniAuth::Strategies::OAuth2
      option :name, 'meister_oauth2'

      option :client_options,
             site: 'https://www.mindmeister.com',
             authorize_url: 'https://www.mindmeister.com/oauth2/authorize',
             token_url: 'https://www.mindmeister.com/oauth2/token'

      uid { raw_info['id'] }

      info do
        {
          name: raw_info['name'],
          email: raw_info['email']
        }
      end

      extra do
        { raw_info: raw_info }
      end

      def raw_info
        log(:info, access_token.to_hash)
        @raw_info ||= access_token.get('https://www.mindmeister.com/api/v2/users/me').parsed
        log(:info, @raw_profile_info)
        @raw_profile_info
      rescue StandardError => e
        log(:error, e)
        raise
      end
    end
  end
end
