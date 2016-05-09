#!/usr/bin/env ruby
#
# Copyright (c) 2011 Jun C. Valdez
# Code is distributed under the terms of an MIT style license
# http://www.opensource.org/licenses/mit-license
#

require 'resolv'
require 'ipaddr'

module Cymru

  module DNSquery
    def intxt(name)
      dns = Resolv::DNS.new
      begin 
        ans = dns.getresources(name, Resolv::DNS::Resource::IN::TXT)
      rescue Resolv::ResolvError
        return arr = "0|0.0.0.0|CC|NIC|Date".split('|').map {|e| e.upcase.strip}
      end
      ans.map { |entry| entry.data.split('|').map {|e| e.upcase.strip} }
    end
  end

  class ASPrefix
    attr_reader :asnum, :asname, :cidr, :country, :registry, :allocdate

    def initialize asnum, asname, cidr, country, registry, allocdate
      @asnum     = asnum
      @asname    = asname
      @cidr      = cidr
      @country   = country
      @registry  = registry
      @allocdate = allocdate
    end
  end
  
  class IPAddress
    include DNSquery
    private :intxt
    
    attr_reader :as_prefixes

    ORIGIN = "origin.asn.cymru.com"
    ORIGIN6 = "origin6.asn.cymru.com"
    BOGON = "bogons.cymru.com"
    
    def initialize
      @as_prefixes = []
    end

    def whois(addr)
      @as_prefixes = [ detailedwhois(addr).first ]
      @as_prefixes.first
    end
  
    def detailedwhois(addr)
      ip = IPAddr.new(addr)
      if ip.ipv4?
        revdns = ip.reverse.sub("in-addr.arpa", ORIGIN)
      elsif ip.ipv6?
        revdns = ip.reverse.sub("ip6.arpa", ORIGIN6)
      end

      ansips = intxt(revdns)

      prefixes = []

      # process all DNS entries returned
      ansips.each do |ansip|
        # process all AS numbers returned per DNS entry
        ansip[0].split.each do |as_number|

          ansip_cidr = ansip[1]

          ansasnum = Cymru::ASNumber.new
          ansasnum.whois(as_number)

          prefixes << ASPrefix.new(as_number, ansasnum.asname, ansip_cidr, ansasnum.country, ansasnum.registry, ansasnum.allocdate)
        end
      end

      @as_prefixes = prefixes
    end
    alias :lookup :whois
    
  end

  class ASNumber
    include DNSquery
    private :intxt 
    
    attr_reader :country, :registry, :allocdate, :asname
    
    ASN = ".asn.cymru.com"

    def initialize
    end
    
    def whois(asn)
      @asn = "AS" + asn + ASN

      ans = intxt(@asn).first
      @country = ans[1]
      @registry = ans[2]
      @allocdate = ans[3]
      @asname = ans[4]
      
      return ans 
    end
    alias :lookup :whois
    
  end
  
end

