# encoding: utf-8

require 'open-uri'
require 'ssrf_filter'

module CarrierWave
  module Uploader
    module Download
      extend ActiveSupport::Concern

      include CarrierWave::Uploader::Callbacks
      include CarrierWave::Uploader::Configuration
      include CarrierWave::Uploader::Cache

      class RemoteFile
        attr_reader :uri

        def initialize(uri, skip_ssrf_protection: false)
          @uri = uri
          @file, @content_type, @headers = nil
          @skip_ssrf_protection = skip_ssrf_protection
        end

        def original_filename
          filename = filename_from_header || File.basename(@uri.path)
          mime_type = MIME::Types[content_type].first
          unless File.extname(filename).present? || mime_type.blank?
            filename = "#{filename}.#{mime_type.extensions.first}"
          end
          filename
        end

        def respond_to?(*args)
          super or file.respond_to?(*args)
        end

        def http?
          @uri.scheme =~ /^https?$/
        end

        def content_type
          file
          @content_type || 'application/octet-stream'
        end

        def headers
          file
          @headers || {}
        end

      private

        # Backport of the CVE-2021-21288 (SSRF) fix: download through SsrfFilter,
        # which refuses private/internal addresses, also when following redirects.
        def file
          if @file.blank?
            if @skip_ssrf_protection
              @file = URI.open(@uri.to_s)
              @file = @file.is_a?(String) ? StringIO.new(@file) : @file
              @content_type = @file.content_type
              @headers = @file.meta
              @uri = @file.base_uri
            else
              request = nil
              response = SsrfFilter.get(@uri, headers: { 'User-Agent' => "CarrierWave/#{CarrierWave::VERSION}" }) do |req|
                request = req
              end
              response.value
              @file = StringIO.new(response.body)
              @content_type = response.content_type
              @headers = response
              @uri = request.uri
            end
          end
          @file

        rescue Exception => e
          raise CarrierWave::DownloadError, "could not download file: #{e.message}"
        end

        def filename_from_header
          if headers['content-disposition']
            match = headers['content-disposition'].match(/filename="?([^"]+)/)
            return match[1] unless match.nil? || match[1].empty?
          end
        end

        def method_missing(*args, &block)
          file.send(*args, &block)
        end
      end

      ##
      # Caches the file by downloading it from the given URL.
      #
      # === Parameters
      #
      # [url (String)] The URL where the remote file is stored
      #
      def download!(uri)
        processed_uri = process_uri(uri)
        file = RemoteFile.new(processed_uri, skip_ssrf_protection: skip_ssrf_protection?(processed_uri))
        raise CarrierWave::DownloadError, "trying to download a file which is not served over HTTP" unless file.http?
        cache!(file)
      end

      ##
      # Processes the given URL by parsing and escaping it. Public to allow overriding.
      #
      # === Parameters
      #
      # [url (String)] The URL where the remote file is stored
      #
      def process_uri(uri)
        URI.parse(uri)
      rescue URI::InvalidURIError
        uri_parts = uri.split('?')
        # regexp from Ruby's URI::Parser#regexp[:UNSAFE], with [] specifically removed
        encoded_uri = URI::DEFAULT_PARSER.escape(uri_parts.shift, /[^\-_.!~*'()a-zA-Z\d;\/?:@&=+$,]/)
        encoded_uri << '?' << URI::DEFAULT_PARSER.escape(uri_parts.join('?')) if uri_parts.any?
        URI.parse(encoded_uri) rescue raise CarrierWave::DownloadError, "couldn't parse URL"
      end

      ##
      # If this returns true, SSRF protection will be bypassed.
      # You can override this if you want to allow accessing specific local URIs that are not SSRF exploitable.
      #
      # === Parameters
      #
      # [uri (URI)] The URI where the remote file is stored
      #
      # === Examples
      #
      #     class MyUploader < CarrierWave::Uploader::Base
      #       def skip_ssrf_protection?(uri)
      #         uri.hostname == 'localhost' && uri.port == 80
      #       end
      #     end
      #
      def skip_ssrf_protection?(uri)
        false
      end

    end # Download
  end # Uploader
end # CarrierWave
