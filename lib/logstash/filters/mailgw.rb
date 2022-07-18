# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require_relative "util/mailgw_constant"
require_relative "util/aerospike_config"
require_relative "store/aerospike_store"

class LogStash::Filters::Mailgw < LogStash::Filters::Base
  include MailgwConstant
  include Aerospike
  config_name "mailgw"

  config :aerospike_server,          :validate => :string,  :default => "",                             :required => false
  config :aerospike_namespace,       :validate => :string,  :default => "malware",                             :required => false
  config :counter_store_counter,     :validate => :boolean, :default => false,                          :required => false
  config :flow_counter,              :validate => :boolean, :default => false,                          :required => false

  # DATASOURCE="rb_flow"
  DELAYED_REALTIME_TIME = 15

  public
  def register
    # Add instance variables
    @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
    @aerospike = Client.new(@aerospike_server)
    @aerospike_store = AerospikeStore.new(@aerospike, @aerospike_namespace)
  end # def register

  public

  def size_to_range(size)
    range  = nil
    if (size < 1024)
        range =  "<1kB"
    elsif(size >= 1024 && size < (1024*1024))
        range = "1kB-1MB"
    elsif(size >= (1024*1024) && size < (10*1024*1024))
        range = "1MB-10MB"
    elsif(size >= (10*1024*1024) && size < (50*1024*1024))
        range = "10MB-50MB"
    elsif(size >= (50*1024*1024) && size < (100*1024*1024))
        range = "50MB-100MB"
    elsif(size >= (100*1024*1024) && size < (500*1024*1024))
        range = "100MB-500MB"
    elsif(size >= (500*1024*1024) && size < (1024*1024*1024))
        range = "500MB-1GB"
    elsif(size >= (1024*1024*1024))
        range = ">1GB"
    end

    return range
  end

  def filter(event)
    message = {}
    message = event.to_hash

    generated_events = [] 

    files = message.get(FILES)
    urls = message.get(URLS)
    ips = message.get("ip")

    # TODO: Check  if we can simply this (one line)
    headers = message.get(HEADERS)
    message.delete!(HEADERS)
    receivers= message.get(EMAIL_DESTINATIONS)
    message.delete!(EMAIL_DESTINATIONS)
    timestamp = message.get(TIMESTAMP)
    message.delete!(TIMESTAMP)
    
    to_druid = {}

    if (ips.nil? and !ips.empty?) 
      ip_score = ips.first[SCORE]
      to_druid["ip_"+SCORE] = ip_score unless ip_score.nil?
    end

    unless receivers.nil?
      receivers.each do |receive| 
        unless files.nil?
          hash_druid = {}
          hash_druid.merge!to_druid
          hash_druid[EMAIL_DESTINATION] = receive

          status = message.get(ACTION)

          hash_druid["status"] = status unless status.nil?

          files.each do |file|
            #TODO : @aerospike_store.update_hash_times(timestamp, file[HASH])
            hash_druid.merge!message

            hash_druid[FILE_NAME] = file["name"] unless file["name"].nil?
            
            hash_druid[FILE_SIZE] = size_to_range(file["size"].to_i) unless file["size"].nil?
            
            score = file[SCORE].to_i
            
            hash_druid["hash_"+PROBE_SCORE] = score unless score.nil?

            hash_druid[HASH] = file[HASH]
            #TODO:  msg_ip_scores = @aerospike_store.enrich_ip_scores(hash_druid)
            #TODO:  msg_hash_scores = @aerospikes.enrich_hash_scores(msg_ip_scores)
            msg_hash_scores[TYPE] = "mail-gw"
            msg_hash_scores[APPLICATION_ID_NAME] = "snmtp"
            
            generated_events.push(LogStash::Event.new(msg_hash_scores))     
          end
          
        end

        unless urls.nil?
          url_druid = {}
          url_druid[EMAIL_DESTINATION] = receive
          url_druid.merge!to_druid
          status = message.get(ACTION).to_s

          url_druid["status"] = status unless status.nil?

          urls.each do |url_map|
            url = url_map[URL].to_s

            unless url.nil?
              #TODO: @aerospike_store.update_hash_times(timestamp,  url)
              url_druid.merge!message
              url_druid[URL] = url

              score = url_map[SCORE].to_i

              url_druid["url_"+PROBE_SCORE] = score unless score.nil?
              #TODO:  msg_ip_scores = @aerospike_store.enrich_ip_scores(hash_druid)
              #TODO:  msg_url_scores = @aerospikes.enrich_url_scores(msg_ip_scores)
              msg_url_scores[TYPE] = "mail-gw"
              msg_url_scores[APPLICATION_ID_NAME] = "smtp"
              generated_events.push(LogStash::Event.new(msg_url_scores)) 
            end
            

          end

        end
      end
    end



    @store_manager.test(message)
    # message_enrichment_store = @store_manager.enrich(message)
    # message_enrichment_store[DURATION]  = calculate_duration(message_enrichment_store)

    # datasource = DATASOURCE
    # if @flow_counter or @counter_store_counter
    #   datasource = store_enrichment[NAMESPACE_UUID] ? DATASOURCE + "_" + store_enrichment[NAMESPACE_UUID] :       DATASOURCE

    #   if @flow_counter 
    #     flows_number = @memcached.get(FLOWS_NUMBER) || {}
    #     message_enrichment_store["flows_count"] = (flows_number[datasource] || 0)
    #   end
    # end

    # splitted_msg = split_flow(message_enrichment_store)

    # splitted_msg.each do |msg|
    #   yield LogStash::Event.new(msg)
    # end 

    # if @counter_store_counter
    #   counter_store = @memcached.get(COUNTER_STORE) || {}
    #   counter = counter_store[datasource] || 0
    #   counter_store[datasource] = counter + splitted_msg.size
    #   @memcached.set(COUNTER_STORE,counter_store)
    # end

    # event.cancel
  end  # def filter(event)
end # class LogStash::Filters::Mailgw
