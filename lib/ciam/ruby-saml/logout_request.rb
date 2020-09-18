require 'uuid'

module Ciam::Saml
  class LogoutRequest
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
    DSIG      = "http://www.w3.org/2000/09/xmldsig#"
    
    include Coding
    include Request
    attr_reader :transaction_id
    attr_accessor :settings
  
    def initialize( options = {} )
      opt = {  :request => nil, :settings => nil  }.merge(options)
      @settings = opt[:settings]
      @issue_instant = Ciam::Saml::LogoutRequest.timestamp
      @request_params = Hash.new
       # We need to generate a LogoutRequest to send to the IdP
      if opt[:request].nil?
        @transaction_id = UUID.new.generate
      # The IdP sent us a LogoutRequest (IdP initiated SLO)
      else
        begin
          @request = Ciam::XMLSecurity::SignedDocument.new( decode( opt[:request] ))
          raise if @request.nil?
          raise if @request.root.nil?
          raise if @request.root.namespace != PROTOCOL
        rescue
          @request = Ciam::XMLSecurity::SignedDocument.new( inflate( decode( opt[:request] ) ) )
        end
        Logging.debug "LogoutRequest is: \n#{@request}"
      end 
    end

    def create( options = {} )
      opt = { :name_id => nil, :session_index => nil, :extra_parameters => nil  }.merge(options)
      return nil unless opt[:name_id]
      
      request_doc = Ciam::XMLSecurityNew::Document.new
      request_doc.context[:attribute_quote] = :quote
      
                                
      root = request_doc.add_element "samlp:LogoutRequest", { "xmlns:samlp" => PROTOCOL, "xmlns:saml" => ASSERTION }
      root.attributes['ID'] = @transaction_id
      root.attributes['IssueInstant'] = @issue_instant
      root.attributes['Version'] = "2.0"
      root.attributes['Destination'] = @settings.single_logout_destination
      
      issuer = root.add_element "saml:Issuer"#, { "xmlns:saml2" => ASSERTION  }
      #issuer.attributes['Format'] = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
      issuer.text = @settings.issuer

      name_id = root.add_element "saml:NameID"#, { "xmlns:saml2" => ASSERTION }
      name_id.attributes['Format'] = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      name_id.attributes['NameQualifier'] = @settings.idp_name_qualifier
      name_id.text = opt[:name_id]
      # I believe the rest of these are optional
      # if @settings && @settings.sp_name_qualifier
      #   name_id.attributes["SPNameQualifier"] = @settings.sp_name_qualifier
      # end
      if opt[:session_index] 
        session_index = root.add_element "samlp:SessionIndex" #, { "xmlns:samlp" => PROTOCOL }
        session_index.text = opt[:session_index]
      end

      request_doc << REXML::XMLDecl.new("1.0", "UTF-8")
      #sign logout_request
      cert = @settings.get_cert(@settings.sp_cert)
      
      # embed signature
      if @settings.metadata_signed && @settings.sp_private_key && @settings.sp_cert
        private_key = @settings.get_sp_key
        request_doc.sign_document(private_key, cert)
      end


      puts "Created LogoutRequest: #{request_doc}"
      
      #Logout per binding redirect
      # meta = Metadata.new(@settings)
      # slo_req = meta.create_slo_request( request_doc.to_s, opt[:extra_parameters] )
      
      
      return request_doc.to_s
      
      #action, content =  binding_select("SingleLogoutService")
      #Logging.debug "action: #{action} content: #{content}"
      #return [action, content]
    end

    # function to return the created request as an XML document
    def to_xml
        text = ""
        @request.write(text, 1)
        return text
    end

    def to_s
        @request.to_s
    end

    # Functions for pulling values out from an IdP initiated LogoutRequest
    def name_id 
      element = REXML::XPath.first(@request, "/p:LogoutRequest/a:NameID", { 
          "p" => PROTOCOL, "a" => ASSERTION } )
      return nil if element.nil?
      # Can't seem to get this to work right...
      #element.context[:compress_whitespace] = ["NameID"]
      #element.context[:compress_whitespace] = :all
      str = element.text.gsub(/^\s+/, "")
      str.gsub!(/\s+$/, "")
      return str
    end
  
    def transaction_id
      return @transaction_id if @transaction_id 
      element = REXML::XPath.first(@request, "/p:LogoutRequest", { 
          "p" => PROTOCOL} )
      return nil if element.nil?
      return element.attributes["ID"]
    end

    def is_valid?
      validate(soft = true)
    end
  
    def validate!
      validate( soft = false )
    end

    def validate( soft = true )
      return false if @request.nil?
        return false if @request.validate(@settings, soft) == false
      
      return true
      
    end

    private 
    
    def self.timestamp
      Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    end
   
  end
end
