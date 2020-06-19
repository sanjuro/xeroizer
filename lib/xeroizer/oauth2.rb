module Xeroizer
  class OAuth2

    attr_reader :client, :access_token

    attr_accessor :tenant_id

    def initialize(client_key, client_secret, options = {})
      @client = ::OAuth2::Client.new(client_key, client_secret, options)
    end

    def authorize_url(params)
      @client.authorize_url(params)
    end

    def request_token(params)
      params[:token_method] = :post
      token = @client.get_token(params)
    end

    def renew_access_token(client_key = nil, client_secret = nil, refresh_token = nil)
      params = {
        client_id: client_key,
        client_secret: client_secret,
        grant_type: 'refresh_token',
        refresh_token: refresh_token
      }
      @client.get_token(params)
    end

    def get_current_connection(params)
      authentication_event_id = params[:token].first["authentication_event_id"]

      @client.authorize_from_access(params[:token])
      current_connections = @client.current_connections

      connection = current_connections.select{|value|
        value.authEventId == authentication_event_id
      }
      connection.first
    end

    def current_connections
      Connection.current_connections(client)
    end

    def authorize_from_access(access_token, options = {})
      @access_token = ::OAuth2::AccessToken.new(client, access_token)
    end

    def get(path, headers = {})
      wrap_response(access_token.get(path, headers: wrap_headers(headers)))
    end

    def post(path, body = "", headers = {})
      wrap_response(access_token.post(path, {body: body, headers: wrap_headers(headers)}))
    end

    def put(path, body = "", headers = {})
      wrap_response(access_token.put(path, body: body, headers: wrap_headers(headers)))
    end

    def delete(path, headers = {})
      wrap_response(access_token.delete(path, headers: wrap_headers(headers)))
    end

    private

    def wrap_headers(headers)
      if tenant_id
        headers.merge("Xero-tenant-id" => tenant_id)
      else
        headers
      end
    end

    def wrap_response(response)
      Response.new(response)
    end

    class Response
      attr_reader :response

      def initialize(response)
        @response = response
      end

      def code
        response.status
      end

      def success?
        (200..299).to_a.include?(code)
      end

      def plain_body
        response.body
      end
    end
  end
end
