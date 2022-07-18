# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require_relative "util/location_constant"
require_relative "util/memcached_config"
require_relative "store/store_manager"

class LogStash::Filters::Mailgw < LogStash::Filters::Base
  include LocationConstant
  config_name "mailgw"

  config :memcached_server,          :validate => :string,  :default => "",                             :required => false
  config :counter_store_counter,     :validate => :boolean, :default => false,                          :required => false
  config :flow_counter,              :validate => :boolean, :default => false,                          :required => false
  config :update_stores_rate,        :validate => :number,  :default => 60,                             :required => false

  DATASOURCE="rb_flow"
  DELAYED_REALTIME_TIME = 15

  public
  def register
    # Add instance variables
    @memcached_server = MemcachedConfig::servers if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0})
    @store_manager = StoreManager.new(@memcached, @update_stores_rate)
  end # def register

  public
  def calculate_duration(msg)
    timestamp = msg[TIMESTAMP]
    first_switched = msg[FIRST_SWITCHED]

    packet_end = (timestamp) ? timestamp.to_i : Time.now.to_i
    packet_start = (first_switched) ? timestamp.to_i : packet_end

    duration = packet_end - packet_start
    duration = 1 if duration < 0
    return duration
  end
 
  def split_flow(msg)
    #longMark = Time.now.to_i
    generated_packets = []
    now = Time.now.utc
    if msg[FIRST_SWITCHED] && msg[TIMESTAMP] 
      packet_start = Time.at(msg[FIRST_SWITCHED]).utc
      packet_end = Time.at(msg[TIMESTAMP]).utc
      now_our = now.hour
      packet_end_hour = packet_end.hour
      
      #// Get the lower limit date time that a packet can have
      limit = (now.min < DELAYED_REALTIME_TIME) ?  (now - (now.hour * 60 * 60) - (now.min * 60) - now.sec) : (now - (now.min * 60) - now.sec)
      
      #// Discard too old events
      if ((packet_end_hour == now.hour - 1 && now.min > DELAYED_REALTIME_TIME) || (now.to_i - packet_end.to_i > 1000 * 60 * 60))
        @logger.debug? && @logger.warn("Dropped packet {} because its realtime processor is already shutdown.")
      elsif packet_start < limit
        #// If the lower limit date time is overpassed, correct it
        @logger.debug? && @logger.warn("Packet {} first switched was corrected because it overpassed the lower limit (event too old).")
        packet_start = limit
        msg[FIRST_SWITCHED] = limit.to_i
      end
       
      #// Correct events in the future
      if (packet_end > now && ((packet_end.hour != packet_start.hour) || (packet_end.to_i - now.to_i > 1000 * 60 * 60)))
        @logger.debug? && @logger.warn("Packet {} ended in a future segment and I modified its last and/or first switched values")
        msg[TIMESTAMP] = now.to_i
        packet_end = now
        
        msg[FIRST_SWITCHED] = now.to_i unless packet_end > packet_start
      end   

      this_end = packet_start
      bytes = pkts = 0
      begin
        bytes = Integer(msg[BYTES]) if msg[BYTES]
      rescue
        @logger.debug? && @logger.warn("Invalid number of bytes in packet")
        return generated_packets
      end
       
      begin
        pkts = Integer(msg[PKTS]) if msg[PKTS]
      rescue
        @logger.debug? && @logger.warn("Invalid number of packets in packet")
        return generated_packets
      end
      
      total_diff = 0

      begin
        total_diff = packet_end.to_i - packet_start.to_i
        diff = this_bytes = this_pkts = nil
        bytes_count = pkts_count = 0
        loop_counter = 0
        loop do 
          loop_counter += 1
          this_start = this_end
          this_end = Time.at(this_start.to_i + (60 - this_start.sec))
          this_end = packet_end if this_end > packet_end
          diff = this_end.to_i - this_start.to_i
          this_bytes = (total_diff == 0) ? bytes : Integer((bytes * diff / total_diff).ceil)
          this_pkts  = (total_diff == 0) ? pkts : Integer((pkts * diff / total_diff).ceil)
          bytes_count += this_bytes
          pkts_count += this_pkts
          
          to_send = {}
          to_send.merge!(msg)
          to_send[TIMESTAMP] = this_start.to_i
          to_send[BYTES] = this_bytes.to_i
          to_send[PKTS] = this_pkts
          to_send.delete(FIRST_SWITCHED)
          generated_packets.push(to_send)
          break if (this_end >= packet_end)
        end
        if (bytes != bytes_count || pkts != pkts_count) 
          last_index = generated_packets.size - 1
          last = generated_packets[last_index]
          new_pkts = Integer(last[PKTS]) + (pkts - pkts_count)
          new_bytes = Integer(last[BYTES]) + (bytes - bytes_count)

          last[PKTS] = new_pkts if new_pkts > 0
          last[BYTES] = new_bytes if new_bytes > 0

           generated_packets[last_index] = last 
        end
      rescue => e
        @logger.debug? && @logger.warn("Invalid time difference in packet #{loop_counter}: #{e.message}")
        return generated_packets
      end
    elsif msg[TIMESTAMP]
      begin  
        if msg[BYTES] 
          bytes = Integer(msg[BYTES])
          msg[BYTES] = bytes
          generated_packets.push(msg)
        else
          @logger.debug? && @logger.warn("No bytes field in event")
          return generated_packets
        end
      rescue
        @logger.debug? && @logger.warn("Invalid number of bytes in packet")
        return generated_packets
      end
    else #.. try..
      begin
        if msg[BYTES]
          bytes = Integer(msg[BYTES])
          msg[BYTES] = bytes
          @logger.debug? && @logger.warn("Packet without timestamp")
          msg[TIMESTAMP] = Time.now.to_i
          generated_events.push(msg)
        else
          @logger.debug? && @logger.warn("No bytes field in event")
          return generated_packets
        end  
      rescue
        @logger.debug? && @logger.warn("Invalid number of bytes in packet")
        return generated_packets
      end
    end

    generated_packets.each do |packet|
     next if generated_packets.index(packet) == 0
     packet.delete(DURATION)
    end
    return generated_packets
  end

  def filter(event)
    message = {}
    message = event.to_hash
    message_enrichment_store = @store_manager.enrich(message)
    message_enrichment_store[DURATION]  = calculate_duration(message_enrichment_store)

    datasource = DATASOURCE
    if @flow_counter or @counter_store_counter
      datasource = store_enrichment[NAMESPACE_UUID] ? DATASOURCE + "_" + store_enrichment[NAMESPACE_UUID] :       DATASOURCE

      if @flow_counter 
        flows_number = @memcached.get(FLOWS_NUMBER) || {}
        message_enrichment_store["flows_count"] = (flows_number[datasource] || 0)
      end
    end

    splitted_msg = split_flow(message_enrichment_store)

    splitted_msg.each do |msg|
      yield LogStash::Event.new(msg)
    end 

    if @counter_store_counter
      counter_store = @memcached.get(COUNTER_STORE) || {}
      counter = counter_store[datasource] || 0
      counter_store[datasource] = counter + splitted_msg.size
      @memcached.set(COUNTER_STORE,counter_store)
    end

    event.cancel
  end  # def filter(event)
end # class LogStash::Filters::Mailgw
