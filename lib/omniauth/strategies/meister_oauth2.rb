require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class MeisterOauth2 < OmniAuth::Strategies::OAuth2
      option :name, 'meister_oauth2'

      option :client_options,
             site: 'https://www.mindmeister.com',
             authorize_url: '/oauth2/authorize',
             token_url: '/oauth2/token'

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

      def callback_url
        options['redirect_uri'] || full_host + script_name + callback_path
      end

      def build_access_token
        verifier = request.params['code']

        params = { redirect_uri: callback_url, client_id: options.client_id, client_secret: options.client_secret, scopes: options.scope }
        client.auth_code.get_token(verifier, params.merge(token_params.to_hash(symbolize_keys: true)), deep_symbolize(options.auth_token_params))
      end

      def raw_info
        @raw_info ||= access_token.get('https://www.mindmeister.com/api/v2/users/me').parsed
      end
    end
  end
end
