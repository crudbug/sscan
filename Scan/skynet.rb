require File.expand_path(File.dirname(__FILE__) + '/skynet_conf.rb')
require 'uri'
require 'net/http'
require 'net/https'
require 'json'
require 'date'
require 'fileutils'
require 'pp'


class Target
  attr_reader :hostname, :hostId, :basic_user, :basic_pass
  
  def initialize(hostname, hostId, basic_user, basic_pass)
    @hostname=hostname
    @hostId=hostId
    @basic_user = basic_user
    @basic_pass = basic_pass
  end
end

 
# get next target from Nosy
#
def getNextTarget
  url = URI(BUCKET_URL)
  
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.ca_file = CA_SAPO

  req = Net::HTTP::Post.new(url.path)
  req['Authorization'] = "Token #{TOKEN}" 
  res = http.request(req)

  if res.kind_of? Net::HTTPSuccess
    response_hash = JSON.parse(res.body)
    pp response_hash
    
    if (response_hash.has_key?('basic_user') and response_hash.has_key?('basic_pass'))
      basic_user = response_hash['basic_user']
      basic_pass = response_hash['basic_pass']
    end
        
    return Target.new(response_hash['hostname'].strip, response_hash['host']['id'], basic_user, basic_pass)
  else
    puts "Got an error: HTTP #{res.code}"
    puts "Error message #{res.body}"
    return nil
  end
end


def startBurp(target)  
  dontScanFlag = DONTSCAN ? "-dtrue" : ""
  basicAuth = (not target.basic_user.nil? and not target.basic_pass.nil?) ? "-b#{target.basic_user}:#{target.basic_pass}" : ""
  burpBin=`ls -1tr #{DIR_PREFIX}/burpsuite_pro* | tail -n 1`
  
  command = "java #{burpBin.strip} -t#{target.hostname} -H#{target.hostId} -w#{BURP_WORKING_DIR} -c#{DEFAULT_CONF} #{dontScanFlag} #{basicAuth} 2>&1"
  puts "executing #{command}"
  output = `#{command}`
  puts output    
  
  if DONTSCAN or !FORCED_TARGET.empty?
    puts "exiting"
    exit(1) 
  end
end

# compresses and cleans Burp logs
# 
def clean(target)
  storageDir = "#{SKYNET_WORKING_DIR}/#{DateTime.now.strftime("%FT%R").gsub(/[\/:]/,"_")}_#{target.hostname.gsub(/[\/:]/,"_")}"
  puts "Doing backup of #{storageDir}..."
  Dir.mkdir(storageDir)
  FileUtils.mv(Dir.glob("#{BURP_WORKING_DIR}/*"), "#{storageDir}/")  
  
  puts "...done"
end

while(true)
  
  if (not Dir.exists?(JAR_AUTOLOAD))
    puts "Directory #{JAR_AUTOLOAD} does not exist"
    exit 1
  end
  
  if (FORCED_TARGET.empty?)
    begin  
      target = getNextTarget()
    rescue Exception => e
      puts 'failed to obtain a new target'
      puts "got error #{e.message}"
      sleep 5
      next
    end
          
   startBurp(target)
   clean(target)    
  
end