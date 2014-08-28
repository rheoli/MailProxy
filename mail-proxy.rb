#!/usr/bin/env ruby

require 'em-proxy'
require 'em-http'
require 'yaml'
require 'net/http'
require 'securerandom'

class ClamAV < EventMachine::Connection

  def initialize(msg, conn)
    @msg = msg
    @ret = ""
    @p_conn = conn
  end

  def post_init
    send_data "zINSTREAM\0"
    pos = 0
    while @msg.size > pos
      max = pos+1024
      max = @msg.size if max > (@msg.size)
p max-pos
p @msg[pos..(max-1)].size
      send_data [max-pos].pack("N")
      send_data @msg[pos..(max-1)]
      pos += 1024
    end
    if pos < @msg.size
p @msg.size-pos
p @msg[pos..(@msg.size-1)].size
      send_data [@msg.size-pos].pack("N")
      send_data @msg[pos..(@msg.size-1)]
    end
    send_data "\0\0\0\0"
    send_data "\0"
  end

  def receive_data(data)
    @ret = data
  end

  def unbind
    msg_new = ""
    if @ret=~/^stream: (.+)\0$/
      state = $1
      if state == "OK"
        msg_new = "X-MailProxy-VC: Clean\r\n#{@msg}"
      else
        File.open("quarantine/#{SecureRandom.uuid}.mail","w") do |f|
          f.write("X-MailProxy-VC: Virus #{state}\r\n#{@msg}")
        end
        @p_conn.send_data "250 2.0.0: Message accepted for delivery\r\n"
        return
      end
    else
      msg_new = "X-MailProxy-VC: Unknown\r\n#{@msg}"
    end
    EventMachine.connect '127.0.0.1', 3030, SpamC, msg_new, @p_conn
  end
end

class SpamC < EventMachine::Connection

  def initialize(msg, conn)
    @msg = msg
    @msg_sa = ""
    @p_conn = conn
  end

  def post_init
    send_data "PROCESS SPAMC/1.2\r\nContent-length: #{@msg.size}\r\n\r\n#{@msg}"
  end

  def receive_data(data)
    @msg_sa += data
  end

  def unbind
    i = @msg_sa.index("\r\n\r\n")
    msg_hdr = @msg_sa[0..(i-1)]
    msg_new = ""
    if msg_hdr=~/^SPAMD\/1.1 0 EX_OK/
      msg_new = "X-MailProxy-SA: OK\r\n#{@msg_sa[(i+4)..(@msg_sa.size-1)]}"
    else
      msg_new = "X-MailProxy-SA: Error\r\n#{@msg}"
    end
    @p_conn.relay_to_servers(msg_new)
  end
end

Proxy.start(:host => "0.0.0.0", :port => 2524) do |conn|
  conn.server :srv, :host => "127.0.0.1", :port => 2424

  RCPT_CMD = /RCPT TO:<(.*)?>\r\n/        # RCPT TO:<name@address.com>\r\n
  FROM_CMD = /MAIL FROM:<(.*)?>\r\n/    # MAIL FROM:<ilya@aiderss.com>\r\n
  MSG_CMD = /^354 /   # 354 Start your message
  MSGEND_CMD = /^.\r\n/

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
      @buffer = false
      #p [:body_scan, @msg]
      EventMachine.connect '127.0.0.1', 3310, ClamAV, @msg, conn
      #EventMachine.connect '127.0.0.1', 3030, SpamC, @msg, conn
      data = nil
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
