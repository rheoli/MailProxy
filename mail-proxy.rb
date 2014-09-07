#!/usr/bin/env ruby

require 'em-proxy'
require 'em-http'
require 'daemons'

require './lib/filter'
require './lib/clamav'
require './lib/spamc'

#Daemons.daemonize

Proxy.start(:host => "0.0.0.0", :port => 2524) do |conn|
  conn.server :srv, :host => "10.73.8.96", :port => 25

  RCPT_CMD = /RCPT TO:<(.*)?>\r\n/        # RCPT TO:<name@address.com>\r\n
  FROM_CMD = /MAIL FROM:<(.*)?>\r\n/    # MAIL FROM:<ilya@aiderss.com>\r\n
  MSG_CMD = /^354 /   # 354 Start your message
  MSGEND_CMD = /^\.\r\n/

  conn.on_data do |data|
    #p [:data, data, @buffer]
    @from = data.match(FROM_CMD)[1] if data.match(FROM_CMD)
    @rcpt = data.match(RCPT_CMD)[1] if data.match(RCPT_CMD)
    @done = true if data.match(MSGEND_CMD)

    if @buffer
      @msg += data
      data = nil
    end

    if @done
      #p [:body_scan, @msg]
      data = nil
      @buffer = false
      
      filter = {
        msg: @msg,
        conn: conn,
        info: {}
        header: []
        filter: [
          {ip: '127.0.0.1', port: 3030, class: SpamC},
          {ip: '127.0.0.1', port: 3310, class: ClamAV},
        ] 
      }
      
      Filter.next_filter(filter)
    end

    data
  end
 
  conn.on_response do |server, resp|
    #p [:res ,resp]

    if !@buffer and resp.match(MSG_CMD)
      @buffer = true
      @msg = ""
    end

    resp
  end
end

#=EOF
