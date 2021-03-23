require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class Qualtrics < OmniAuth::Strategies::OAuth2

      option :name, "qualtrics"

      option :client_options,
            site:          "https://iad1.qualtrics.com",
            authorize_url: "/oauth2/auth",
            token_url:     "/oauth2/token"

      # Qualtrics does use state but we want to control it rather than letting
      # omniauth-oauth2 handle it.
      option :provider_ignores_state, true

      option :token_params, parse: :json

      uid do
        access_token["user"]["id"]
      end

      info do
        {
          "name" => raw_info["name"],
          "url" => access_token.client.site
        }
      end

      # Override authorize_params so that we can be deliberate about the value for state
      # and not use the session which is unavailable inside of an iframe for some
      # browsers (ie Safari)
      def authorize_params
        # Only set state if it hasn't already been set
        options.authorize_params[:state] ||= SecureRandom.hex(24)
        params = options.authorize_params.merge(options_for("authorize"))
        if OmniAuth.config.test_mode
          @env ||= {}
          @env["rack.session"] ||= {}
        end
        params
      end

    end
  end
end

OmniAuth.config.add_camelization "qualtrics", "Qualtrics"
