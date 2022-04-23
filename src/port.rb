require './src/ipv4'

include Socket::Constants

# Represents a port in the router, stores IP address and the name.
class Port
    
    PORT_TYPES = [:peer, :prov, :cust]

    def initialize(ip, type)
        @ip = ip
        @neighbor = ip.succ
        @type = type
    end

    # static -----------------------------------------------------------------
    
    # parse: String -> Port
    # Parse string representation of the neighbor into Port.
    def Port.parse(neighbor)
        ip, type = neighbor.split("-")

        abort "ABORT: no port type for IP:#{ip}" if type.nil? or type.empty?
        type = type.to_sym
        abort "ABORT: unrecognized port type for IP:#{ip}" unless PORT_TYPES.include?(type)
        
        ip = IPv4.parse(ip)
        port_ip = IPv4.pred(ip)

        Port.new(port_ip, type)
    end

    # public -----------------------------------------------------------------

    # open: -> Nil
    # Connect using UNIXSocket to the host specified by @neighbor.
    def open
        @socket = Socket.new(AF_UNIX, SOCK_SEQPACKET)
        begin
            @socket.connect(Socket.pack_sockaddr_un(@neighbor.to_s))
        rescue
            abort "ABORT: port #{to_s} connection failed\n#{$!}"
        end
    end

    # close: -> Nil
    # Close the port.
    def close
        @socket.close unless @socket.nil?
    end

    # get: _ -> Packet
    # Get packet from the stream port.
    def get_packet
        data, _ = @socket.recvfrom(65535)
        packet = Packet.parse(data)
        packet.show_with(:received, @ip) if DEBUG
        packet
    end

    # send_msg: Message -> Unit
    # Send given Message.
    def send_msg(msg)
        send_packet(Packet.new(@ip, @neighbor, msg.type, msg))
    end

    # send_msg: Message -> Unit
    # Send given Message with modified destination
    def send_msg_to(dst, msg)
        send_packet(Packet.new(@ip, dst, msg.type, msg))
    end

    # send: Packet -> Unit
    # Send given packet.
    def send_packet(packet)
        packet.show_with(:send, @ip) if DEBUG
        @socket.write(packet.to_json)
    end

    # type?: Symbol -> Bool
    # Are you this type?
    def type?(type)
        @type == type
    end

    # connect_to?: IPAddr -> Bool
    # Are you connected to the given neighbor?
    def connects_to?(neighbor)
        @neighbor == neighbor
    end

    # same?: Port -> Bool
    # Are we the same?
    def same?(other)
        self == other
    end

    # to_s: -> String
    # String representation of the port.
    def to_s
        "#{@ip}-#{@type}"
    end
    
    # to_art: -> String
    # ASCII art representation of the port.
    def to_art
        status = (@socket.nil? or @socket.closed?) ? "X" : "O"
        "~~[#{@type}]~#{status} #{@ip} "
    end
end
