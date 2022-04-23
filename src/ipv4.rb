require 'ipaddr'

# IPv4 module to deal with IPAddr.
module IPv4
    
    # parse: String -> IPAddr
    # Parse IPv4 address as string.
    def IPv4.parse(ip) 
        abort "ABORT: IP address is empty" if ip.nil? or ip.empty?
        begin
            ip = IPAddr.new(ip)
            abort "ABORT: not IPv4 address: #{ip}" unless ip.ipv4?
        rescue
            abort "ABORT: failed to parse port IP"
        else
            ip
        end
    end

    # subnet: IPAddr, IPAddr -> IPAddr
    # Apply netmask to network to get a subnet.
    def IPv4.subnet(network, netmask)
        begin 
            subnet = network.mask(netmask.to_s)
        rescue
            abort "ABORT: netmask #{netmask} very bad, much oof"  
        else
            subnet
        end
    end

    # pred: IPAddr -> IPAddr
    # Get the pred of the IPAddr.
    def IPv4.pred(ip)
        IPAddr.new(ip.to_i - 1, Socket::AF_INET)
    end

    # to_b: IPAddr -> Array[Int]
    # Transform given ip into an array of integers.
    def IPv4.to_b(ip)
        ip.to_i.to_s(2).chars.map(&:to_i)
    end

    # to_b: IPAddr -> Int
    # Find the length/prefix of the given mask.
    # Note: this will not break if not a mask is given,
    #       however result would not be meaningful.
    def IPv4.prefix(ip)
        IPv4.to_b(ip).count(1) 
    end
end
