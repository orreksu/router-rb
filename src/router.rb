require 'thread'
require './src/port'
require './src/packet'
require './src/table'

# global constants
DEBUG = false

# represents a router
class Router

    def initialize(asn, hops)
        @asn = asn
        @ports = hops.map { |n| Port.parse(n) }
        @table = Table.new()
        @status = :off
        show if DEBUG
    end

    # public -----------------------------------------------------------------

    # Turn on the router.
    def on
        @ports.each(&:open)
        @status = :on
        show if DEBUG
        run
    end

    # Turn off the router.
    # TODO: This is never invoked!
    def off
        @ports.each(&:close)
        @status = :off
        self.show if DEBUG
    end

    private # ----------------------------------------------------------------

    # Run the main execution loop.
    def run
        mutex = Mutex.new
        threads = @ports.map { |p| Thread.new { run_port(p, mutex) } }
        threads.each(&:join)
    end

    # run_port: Port, Mutex -> Nil
    # Run the execution loop for given port.
    def run_port(port, mutex)
        loop do
            packet = port.get_packet
            route(packet, port, mutex)
        end
    end

    # route: Packet, Port, Mutex -> Nil
    # Route packet from_port to designated destination, also do updates if required.
    def route(packet, from_port, mutex)
        case packet.type
        when :update
            process_update_packet(packet, from_port, mutex)
        when :revoke
            process_revoke_packet(packet, from_port, mutex)
        when :data
            try_forward_data_packet(packet, from_port)
        when :dump
            send_table_msg(from_port, mutex)
        else 
            abort "ABORT: unsupported request type"
        end
    end

    # process_update_packet: Packet, Port, Mutex -> Nil
    # Update table with the new update, forward update to hops. 
    # NOTE: Update history is kept inside the table.
    def process_update_packet(packet, from_port, mutex)
        mutex.synchronize { @table.update!(packet.clone) }
        forward_msg_to_hops(packet.msg.clone_with_asn(@asn), from_port)
    end

    # process_revoke_packet: Packet, Port, Mutex -> Nil
    # Revoke routes from the table given in packet, forward update to hops.
    # NOTE: Revoke history is kept inside the table.
    def process_revoke_packet(packet, from_port, mutex)
        mutex.synchronize { @table.revoke!(packet.clone) }
        forward_msg_to_hops(packet.msg.clone, from_port)
    end

    # forward_msg_to_hops: Message, Port -> Nil
    # Forward revoke message to or from all other custumers.
    def forward_msg_to_hops(msg, from_port)
        @ports.each do |port|
            next if port.same?(from_port)
            next unless from_port.type?(:cust) or port.type?(:cust)
            port.send_msg(msg)
        end
    end

    # try_forward_data_packet: Packet, Port -> Nil
    # Forward received data packet unmodified to designated destination.
    # If there is no route         -> dump
    # If not to or from a custumer -> dump
    # Otherwise                    -> forward
    def try_forward_data_packet(packet, from_port)

        # there is no route
        unless @table.has_hop_to?(packet.dst)
            from_port.send_msg_to(packet.src, NoRouteMessage.new)
            return
        end

        # get the next hop and the to_port
        hop = @table.get_hop_to(packet.dst)
        to_port = get_port_to(hop)

        # message is not to or from a custumer
        unless from_port.type?(:cust) or to_port.type?(:cust)
            from_port.send_msg_to(packet.src, NoRouteMessage.new)
            return
        end

        to_port.send_packet(packet)
    end

    # get_port_to: IPAddr -> Port
    # Find a the port that leads to given hop ip.
    def get_port_to(hop)
        port = @ports.find { |port| port.connects_to?(hop) }
        abort "No port is associated with given hop ip" if port.nil?
        port
    end

    # process_dump_packet: Port, Mutex -> Nil
    # Send forwarding table as a messsage to_port.
    def send_table_msg(to_port, mutex)
        mutex.synchronize { to_port.send_msg(@table.to_msg) }
    end

    # show: -> Nil
    # Show router as ASCII art.
    def show
        puts to_art
    end
    
    # to_s: -> String
    # String representation of the router.
    def to_s
        ports = @ports.map(&:to_s).join("\n")
        "asn: #{@asn}\n ports:\n #{ports}"
    end
    
    # to_art: -> String
    # ASCII art representation of the router.
    def to_art
        ports = @ports.map { |p| " | {]~^#{p.to_art}"}.join("\n")

        "\n +----+\n"\
          " | [] | ~ ASN: #{@asn}\n"\
          " | -- |\n"\
          "#{ports}\n"\
          " |    |\n"\
          " | .: |\n"\
          " +-)--+\n"\
          "  ( #{@status}\n\n"
    end
end

# parse: -> Integer, Array[String]
# Parse arguments for the router.
def parse
    args = ARGV

    asn = args.shift.to_i
    abort "ABORT: ASN not given" if asn.nil?

    hops = args
    abort "ABORT: NEIGHBORS not given" if hops.nil? or hops.empty?

    return asn, hops
end

# main: -> Nil
# Script entry point.
def main
    asn, hops = parse
    router = Router.new(asn, hops)
    router.on
    router.off
end