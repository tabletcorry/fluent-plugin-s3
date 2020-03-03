require 'fluent/plugin/parser'
require 'oj'

module Fluent::Plugin
  class JsonCloudTrail < Parser
    # Register this parser as "time_key_value"
    Fluent::Plugin.register_parser("json_cloudtrail", self)

    def configure(conf)
      super
    end

    def parse(text)
      body = Oj.load(text)
      body["Records"].each do |record|
        event_time = Time.parse(record["eventTime"])
        record.delete("eventTime")
        yield event_time, record
      end
    end
  end
end