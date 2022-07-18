# encoding: utf-8
require "aerospike"
require_relative "../util/mailgw_constant"

class AerospikeStore
  include MailgwConstant
  include Aerospike

  attr_accessor :aerospike

  def initialize(aerospike, namespace = "malware")
    @aerospike = aerospike
    @namespace = namespace 
  end

  def test(message)
    key = Key.new(@namespace, 'test_set', 'test_key')
    value = '{ "pepito" : 666 }'
    @aerospike.put(key, value)
  end

  # def enrich(message)
  #   update_stores if (Time.now - @last_stores_update) > @update_stores_rate    
  #   enrichment = {}
  #   enrichment.merge!(message)
  
  #   @stores_list.each_with_index do |store_name,index|
  #     # Lets skip the historical stores, we will check later in case is not found on the current ones.
  #     next if store_name.end_with?"-historical"
  #     if store_name == SENSOR_PSQL_STORE || store_name == WLC_PSQL_STORE
  #       store_data = @stores[store_name]
  #       next unless store_data
  #       keys = get_store_keys(store_name)
  #       namespace = message[NAMESPACE_UUID]
  #       namespace = nil if (namespace && namespace.empty?)
  #       merge_key =""
  #       keys.each{ |k| merge_key += enrichment[k].to_s if enrichment[k] }
  #       contents = store_data[merge_key]
  #       if contents.nil?
  #         key = enrichment[keys.first] ? keys.first : nil
  #         contents = store_data[key.to_s] if key
  #       end
  #       if contents
  #          psql_namespace = contents[NAMESPACE_UUID]
  #          psql_namespace = nil if (psql_namespace && psql_namespace.empty?)
  #          if namespace && psql_namespace
  #              if namespace == psql_namespace
  #                must_overwrite?(store_name) ? enrichment.merge!(contents) : enrichment = contents.merge(enrichment)
  #              end
  #          else
  #              must_overwrite?(store_name) ? enrichment.merge!(contents) : enrichment = contents.merge(enrichment)
  #          end
  #       end      
  #     else
  #       store_data = @stores[store_name]
  #       next unless store_data
  #       keys = get_store_keys(store_name)
  #       merge_key = ""
  #       keys.each{ |k| merge_key += enrichment[k] if enrichment[k] }
  #       contents = store_data[merge_key]
  #       # If no contents on the current one and the store has an historical one, check the historical also
  #       if contents.nil? and @historical_stores.include?"#{store_name}-historical"
  #         contents = @stores["#{store_name}-historical"][merge_key] if @stores["#{store_name}-historical"]
  #       end
  #       must_overwrite?(store_name) ? enrichment.merge!(contents) : enrichment = contents.merge(enrichment) if contents
  #     end
  #   end
  #     return enrichment.reject { |k,v| v.nil? || (v.is_a?Hash) }
  # end
end
