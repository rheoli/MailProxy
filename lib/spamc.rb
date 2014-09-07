class SpamC < EventMachine::Connection

  def self.allowed?(filter)
    return false if @filter[:msg].size >= (500*1024)
    true
  end

  def initialize(filter)
    @filter = filter
    @msg_sa = ""
  end

  def post_init
    send_data "PROCESS SPAMC/1.2\r\nContent-length: #{@filter[:msg].size+2}\r\n\r\n#{@filter[:msg]}\r\n"
  end

  def receive_data(data)
    @msg_sa += data
  end

  def unbind
    i = @msg_sa.index("\r\n\r\n")
    msg_hdr = ""
    if i.nil?
      p @msg_sa
    else
      msg_hdr = @msg_sa[0..(i-1)]
    end

    if msg_hdr=~/^SPAMD\/1.1 0 EX_OK/
      @filter[:header] << "X-MailProxy-SA: OK"
      @filter[:msg] = @msg_sa[(i+4)..(@msg_sa.size-1)]
    else
      @filter[:header] << "X-MailProxy-SA: Error"
    end
    @filter[:info]["spamc"] = true
    
    Filter.next_filter(@filter)
  end
end