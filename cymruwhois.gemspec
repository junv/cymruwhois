require "rubygems"

Gem::Specification.new do |s|
    s.name = "cymruwhois"
    s.version = "0.2.0"
    s.license = "MIT"
    s.author = "Jun C. Valdez"
    s.email = "rubygems@sploitlabs.com"
    s.files = ["lib/cymruwhois.rb","README.rdoc", "History.txt", "cymruwhois.gemspec"]
    s.summary = "cymru is a module that utilizes Team Cymru's IP to ASN Mapping"
    s.description = %q{cymruwhois is a simple Ruby module that utilizes Team Cymru's IP to ASN Mapping
via DNS queries. The module was conceived as an IP geolocation alternative to GeoIP.

Kindly take note of Team Cymru's "Special Notice" for bulk queries at the
top of the page: http://www.team-cymru.org/Services/ip-to-asn.html}

end

