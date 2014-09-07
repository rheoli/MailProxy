require 'securerandom'

class ClamAV < EventMachine::Connection

  def self.allowed?(filter)
    true
  end

  def initialize(filter)
    @filter = filter
    @msg_cl = ""
  end

  def post_init
    send_data "zINSTREAM\0"
    pos = 0
    while @filter[:msg].size > pos
      max = pos+1024
      max = @filter[:msg].size if max > (@filter[:msg].size)
      send_data [max-pos].pack("N")
      send_data @filter[:msg][pos..(max-1)]
      pos += 1024
    end
    if pos < @filter[:msg].size
      send_data [@filter[:msg].size-pos].pack("N")
      send_data @filter[:msg][pos..(@filter[:msg].size-1)]
    end
    send_data "\0\0\0\0"
    send_data "\0"
  end

  def receive_data(data)
    @msg_cl = data
  end

  def unbind
    if @msg_cl=~/^stream: (.+)\0$/
      state = $1
      if state == "OK"
        @filter[:header] << "X-MailProxy-VC: Clean"
      else
        @filter[:header] << "X-MailProxy-VC: Virus #{state}"
        #p_conn.send_data "250 2.0.0: Message accepted for delivery\r\n"
      end
    else
      @filter[:header] << "X-MailProxy-VC: Unknown"
    end
    @filter[:info]["clamav"] = true
    
    Filter.next_filter(@ßfilter)
  end
end