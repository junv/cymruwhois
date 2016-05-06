require 'spec_helper'

describe Cymru do
  describe '#detailedwhois method returns an array of ASPrefix objects' do
    it 'should return an array of ASPrefix objects' do
      cymru = Cymru::IPAddress.new
      as_prefixes = cymru.detailedwhois '194.65.37.71'

      expect(as_prefixes).to be_a Array

      as_prefixes.each do |entry|
        expect(entry).to be_a Cymru::ASPrefix

        expect(entry).to respond_to :asnum
        expect(entry).to respond_to :asname
        expect(entry).to respond_to :cidr
        expect(entry).to respond_to :country
        expect(entry).to respond_to :registry
        expect(entry).to respond_to :allocdate
      end
    end
  end

  describe '#whois method returns an ASPrefix object' do
    it 'should return an ASPrefix object' do
      cymru = Cymru::IPAddress.new
      as_prefix = cymru.whois '194.65.37.71'

      expect(as_prefix).to be_a Cymru::ASPrefix

      expect(as_prefix).to respond_to :asnum
      expect(as_prefix).to respond_to :asname
      expect(as_prefix).to respond_to :cidr
      expect(as_prefix).to respond_to :country
      expect(as_prefix).to respond_to :registry
      expect(as_prefix).to respond_to :allocdate
    end
  end

  describe '#as_prefixes returns an array of ASPrefix objects' do
    context 'when whois is called' do
      it 'should return an array with a single ASPrefix object' do
        cymru = Cymru::IPAddress.new
        cymru.whois '194.65.37.71'

        as_prefixes = cymru.as_prefixes
        as_prefix   = as_prefixes.first

        expect(as_prefixes).to be_a Array
        expect(as_prefixes.size).to eq 1
        
        expect(as_prefix).to be_a Cymru::ASPrefix

        expect(as_prefix).to respond_to :asnum
        expect(as_prefix).to respond_to :asname
        expect(as_prefix).to respond_to :cidr
        expect(as_prefix).to respond_to :country
        expect(as_prefix).to respond_to :registry
        expect(as_prefix).to respond_to :allocdate
       end
    end

    context 'when detailedwhois is called' do
      it 'should return an array with as manyi ASPrefix objects as registered ASes' do
        cymru = Cymru::IPAddress.new
        cymru.detailedwhois '194.65.37.71'

        as_prefixes = cymru.as_prefixes

        expect(as_prefixes).to be_a Array

        as_prefixes.each do |entry|
          expect(entry).to be_a Cymru::ASPrefix

          expect(entry).to respond_to :asnum
          expect(entry).to respond_to :asname
          expect(entry).to respond_to :cidr
          expect(entry).to respond_to :country
          expect(entry).to respond_to :registry
          expect(entry).to respond_to :allocdate
        end
      end
    end
  end
end

