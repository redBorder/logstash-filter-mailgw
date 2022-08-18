# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require_relative "util/malware_constant"
require_relative "util/aerospike_config"
require_relative "store/aerospike_store"

class LogStash::Filters::Mailgw < LogStash::Filters::Base
  include MalwareConstant
  include Aerospike

  config_name "mailgw"

  config :aerospike_server,          :validate => :string,  :default => "",                             :required => false
  config :aerospike_namespace,       :validate => :string,  :default => "malware",                      :required => false
  config :counter_store_counter,     :validate => :boolean, :default => false,                          :required => false
  config :flow_counter,              :validate => :boolean, :default => false,                          :required => false
  config :reputation_servers,        :validate => :array,   :default => ["127.0.0.1:7777"],             :require => false

  # DATASOURCE="rb_flow"
  DELAYED_REALTIME_TIME = 15

  public
  def register
    # Add instance variables
    @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
    @aerospike = Client.new(@aerospike_server.first.split(":").first)
    @aerospike_store = AerospikeStore.new(@aerospike, @aerospike_namespace,  @reputation_servers)

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

    files = message[FILES]
    urls = message[URLS]
    ips = message["ip"]

    # TODO: Check  if we can simply this (one line)
    headers = message[HEADERS]
    message.delete(HEADERS)
    receivers= message[EMAIL_DESTINATIONS]
    message.delete(EMAIL_DESTINATIONS)
    timestamp = message[TIMESTAMP]
    
    to_druid = {}

    if (!ips.nil? and !ips.empty?) 
      ip_score = ips.first[SCORE]
      to_druid["ip_"+SCORE] = ip_score unless ip_score.nil?
    end

    unless receivers.nil?
      receivers.each do |receive| 
        unless files.nil?
          hash_druid = {}
          hash_druid.merge!to_druid
          hash_druid[EMAIL_DESTINATION] = receive

          status = message[ACTION]

          hash_druid["status"] = status unless status.nil?

          files.each do |file|
            @aerospike_store.update_hash_times(timestamp, file[HASH], "hash")
            hash_druid.merge!message

            hash_druid[FILE_NAME] = file["name"] unless file["name"].nil?
            
            hash_druid[FILE_SIZE] = size_to_range(file["size"].to_i) unless file["size"].nil?
            
            score = file[SCORE].to_i
            
            hash_druid["hash_"+PROBE_SCORE] = score unless score.nil?

            hash_druid[HASH] = file[HASH]
            msg_ip_scores = @aerospike_store.enrich_ip_scores(hash_druid)
            msg_hash_scores = @aerospike_store.enrich_hash_scores(msg_ip_scores)
            msg_hash_scores[TYPE] = "mail-gw"
            msg_hash_scores[APPLICATION_ID_NAME] = "snmtp"

            msg_hash_scores["output_topic"] = "rb_malware_post"
            
            generated_events.push(LogStash::Event.new(msg_hash_scores))     
          end
          
        end

        unless urls.nil?
          url_druid = {}
          url_druid[EMAIL_DESTINATION] = receive
          url_druid.merge!to_druid
          status = message[ACTION].to_s

          url_druid["status"] = status unless status.nil?

          urls.each do |url_map|
            url = url_map[URL].to_s

            unless url.nil?
              @aerospike_store.update_hash_times(timestamp,  url, "url")
              url_druid.merge!message
              url_druid[URL] = url

              score = url_map[SCORE].to_i

              url_druid["url_"+PROBE_SCORE] = score unless score.nil?
              msg_ip_scores = @aerospike_store.enrich_ip_scores(url_druid)
              msg_url_scores = @aerospike_store.enrich_url_scores(msg_ip_scores)
              msg_url_scores[TYPE] = "mail-gw"
              msg_url_scores[APPLICATION_ID_NAME] = "smtp"

              msg_url_scores["output_topic"] = "rb_malware_post"
              generated_events.push(LogStash::Event.new(msg_url_scores)) 
            end
          end
        end
      end
    end

    action = message[ACTION]
    email_id = message[EMAIL_ID]

    email_id_key = Key.new(@aerospike_namespace, "mailQuarantine", email_id) rescue nil
    
    if (!action.nil? and action == "QUARANTINE")
      unless email_id.nil?
        sender = message[EMAIL_SENDER]
        
        files_count = files.count rescue 0 
        urls_count = urls.count rescue 0

        q_data = {}
        q_data[TIMESTAMP] = timestamp
        q_data[EMAIL_ID] = email_id
        q_data["email_src"] = sender
        q_data["email_dsts"] = receivers.joint(",")
        q_data["files"] = files_count
        q_data["urls"] = urls_count

        sensor_uuid = message["sensor_uuid"]
        q_data["sensor_uuid"] = sensor_uuid unless sensor_uuid.nil?

        sensor_name = message[SENSOR_NAME]
        q_data[SENSOR_NAME] = sensor_name unless sensor_name.nil?

        @aerospike.put(email_id_key, q_data)

      end
    end

    if (!action.nil? and (action == "QUARANTINE_RELEASE" or action == "QUARANTINE_DROP"))
      @aerospike.delete(email_id_key) if @aerospike.exists(email_id_key)
    end

    subject = message[SUBJECT];
    to_mail = {}
    sensor_uuid = message["sensor_uuid"]

    to_mail["sensor_uuid"] = sensor_uuid unless sensor_uuid.nil?

    to_mail[HEADERS] = headers
    to_mail[EMAIL_ID] = email_id
    to_mail[TYPE] = "mail-gw"
    to_mail[TIMESTAMP] = timestamp
    to_mail["output_topic"] = "rb_mail_post"
    generated_events.push(LogStash::Event.new(to_mail))

    #TODO: check wtf happen with the NAMESPACE and so on.. 

    generated_events.each do |e|
      yield e
    end
    event.cancel
  end  # def filter(event)
end # class LogStash::Filters::Mailgw
