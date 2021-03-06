# OmniAuth Qualtrics [![Build Status](https://travis-ci.org/atomicjolt/omniauth-qualtrics.svg?branch=master)](https://travis-ci.org/atomicjolt/omniauth-qualtrics)
Gem to authenticate with Qualtrics via OAuth2

# Setup
Contact Qualtrics administrator to get an OAuth key and secret and OAuth endpoint
https://api.qualtrics.com/instructions/docs/Instructions/oauth-authentication-authorization-code.md


**NOTE**: you will need to set `env['rack.session']['oauth_site']` to the current
Qualtrics instance that you wish to OAuth with. By default this is https://co1.qualtrics.com

-- OR --

to dynamically set the qualtrics site url do one of the following.

## Standard setup

```ruby
use OmniAuth::Builder do
  provider :qualtrics, 'qualtrics_key', 'qualtrics_secret', :setup => lambda{|env|
    request = Rack::Request.new(env)
    env['omniauth.strategy'].options[:client_options].site = env['rack.session']['oauth_site']
  }
end
```

## Setup with Devise

```ruby
config.omniauth :qualtrics, 'qualtrics_key', 'qualtrics_secret', :setup => lambda{|env|
  request = Rack::Request.new(env)
  env['omniauth.strategy'].options[:client_options].site = env['rack.session']['oauth_site']
}
```

## Alternative Setup

In this setup, you do not have to set `env['rack.session']['oauth_site']`

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :qualtrics, APP_CONFIG['qualtrics_client_id'], APP_CONFIG['qualtrics_client_secret'],
  {
    :client_options => {
      :site => APP_CONFIG['qualtrics_host']
    }
  }
end
```

# State

In most cases your application will need to restore state after handling the OAuth process
with Qualtrics. Since many applications that integrate with Qualtrics will be launched via the LTI
protocol inside of an iframe sessions may not be available. To restore application state the
omniauth-qualtrics gem uses the "state" parameter provided by the LTI proctocol. You will need
to add the following code to your application to take advantage of this functionality:


Add the following initializer in `config/initializers/omniauth.rb`:

```ruby
OmniAuth.config.before_request_phase do |env|
  request = Rack::Request.new(env)
  state = "#{SecureRandom.hex(24)}#{DateTime.now.to_i}"
  OauthState.create!(state: state, payload: request.params.to_json)
  env["omniauth.strategy"].options[:authorize_params].state = state

  # Bye default omniauth will store all params in the session. The code above
  # stores the values in the database so we remove the values from the session
  # since the amount of data in the original params object will overflow the
  # allowed cookie size
  env["rack.session"].delete("omniauth.params")
end
```

Add the following middleware to `lib/middlware/oauth_state_middleware.rb`:

```ruby
class OauthStateMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    request = Rack::Request.new(env)
    if request.params["state"] && request.params["code"]
      if oauth_state = OauthState.find_by(state: request.params["state"])
        # Restore the param from before the OAuth dance
        state_params = JSON.parse(oauth_state.payload) || {}
        state_params.each do |key, value|
          request.update_param(key, value)
        end
        application_instance = ApplicationInstance.find_by(lti_key: state_params["oauth_consumer_key"])
        env["qualtrics.url"] = application_instance.lti_consumer_uri
        oauth_state.destroy
      else
        raise OauthStateMiddlewareException, "Invalid state in OAuth callback"
      end
    end
    @app.call(env)
  end
end

class OauthStateMiddlewareException < RuntimeError
end
```

This middleware relies upon two models - OauthState and ApplicationInstance. OauthState is used to
store relevant state before sending the user to Qualtrics to finish the OAuth. ApplicationInstance is
model used in Atomic Jolt projects that is used to store the Qualtrics Url so that it can be reset in
the environment. You don't need to implement the same model, but you will need to store the user's
Qualtrics URL somewhere before sending the user to OAuth with Qualtrics. Change the following lines in the
above code to recover the Qualtrics URL from where ever it is stored:

```
application_instance = ApplicationInstance.find_by(lti_key: state_params["oauth_consumer_key"])
env["qualtrics.url"] = application_instance.lti_consumer_uri
```

The OauthState model looks like this:
```
class OauthState < ActiveRecord::Base
  validates :state, presence: true, uniqueness: true
end
```

With the following schema:
```
create_table "oauth_states", force: :cascade do |t|
  t.string   "state"
  t.text     "payload"
  t.datetime "created_at", null: false
  t.datetime "updated_at", null: false
  t.index ["state"], name: "index_oauth_states_on_state", using: :btree
end
```

Last, enable the middleware by adding the following to `config/application.rb`:

```ruby
# Middleware that can restore state after an OAuth request
config.middleware.insert_before 0, "OauthStateMiddleware"
```


# License

Copyright (C) 2012-2021  Atomic Jolt.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
