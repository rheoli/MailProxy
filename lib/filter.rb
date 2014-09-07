class Filter
  def self.next_filter(filter)
    connected = false
    while not connected
      next_filter = filter[:filter].pop
      break if next_filter.nil?
      if next_filter[:class].allowed?(filter)
        connected = true
        EventMachine.connect next_filter[:ip], next_filter[:port], next_filter[:class], filter
        break
      end
    end
    unless connected
      if filter[:info].size < 1
        filter[:header] << "Mail-Proxy: No Filter found"
      end
      header = filter[:header].join("\r\n")
      filter[:conn].relay_to_servers("#{header}\r\n#{filter[:msg]}")
    end
    connected
  end
end