require 'json'
require './src/ipv4'

# Represents a packet, that contians src, dst, type, and message.
# They can be send or received by the router using ports.
class Packet

    MESSAGE = {
        :update     => ->(x){ UpdateMessage.parse(x) },
        :revoke     => ->(x){ RevokeMessage.parse(x) },
        :data       => ->(x){ DataMessage.parse(x) },
        :"no route" => ->(x){ NoRouteMessage.parse(x) },
        :dump       => ->(x){ DumpMessage.parse(x) },
        :table      => ->(x){ TableMessage.parse(x) }
    }

    def initialize(src, dst, type, msg)
        abort "ABORT: unknown message type\n" unless MESSAGE.key?(type)
        @src = src
        @dst = dst
        @type = type
        @msg = msg
    end

    attr_reader :src, :dst, :type, :msg

    # static -----------------------------------------------------------------

    # parse: String -> Packet
    # Parse given json string into Packet.
    def Packet.parse(data)
        packet = JSON.parse(data, {:symbolize_names=>true})
        
        abort "ABORT: message does not contain SRC\n" unless packet.key?(:src) 
        abort "ABORT: message does not contain DST\n" unless packet.key?(:dst)
        abort "ABORT: message does not contain TYPE\n" unless packet.key?(:type)
        abort "ABORT: message does not contain MSG\n" unless packet.key?(:msg)
        
        src = IPv4.parse(packet[:src])
        dst = IPv4.parse(packet[:dst])
        
        type = packet[:type]
        type = type.to_sym
        abort "ABORT: unknown message type\n" unless MESSAGE.key?(type)

        msg = MESSAGE[type].call(packet[:msg])
        
        Packet.new(src, dst, type, msg)
    end

    # public -----------------------------------------------------------------

    # to_json: -> String
    # Json string representation of the packet.
    def to_json
        JSON.generate(to_prejson)
    end

    # to_hashmap: -> Hash[Symbol, Any]
    # Returns a hashmap, taht can be used to generate Json.
    def to_prejson
        {
            :src  => @src, 
            :dst  => @dst, 
            :type => @type, 
            :msg  => @msg.to_prejson
        }
    end

    # show_with: Symbol, IPAddr -> Nil
    # Show package based on the action and with port ip.
    def show_with(action, port)
        case action
        when :received
            puts "RECEIVED #{@type}\n  port(#{port}), src(#{@src}), dst(#{@dst})\n  msg: #{@msg.to_art}" + "\n\n"
        when :send
            puts "SEND #{@type}\n  port(#{port}), src(#{@src}), dst(#{@dst})\n  msg: #{@msg.to_art}" + "\n\n"
        end
    end

    # to_s: -> String
    # String representation of the package.
    def to_s
        "src: #{@src.to_s}\ndst: #{@dst.to_s}\ntype: #{@type.to_s}\nmsg: #{@msg}"
    end

    # to_art: -> String
    # ASCII art representation of the package.
    def to_art
        "from: #{@src}\n"\
        "type: #{@type}\n"\
        "to: #{@dst}\n"\
        "msg: \n#{@msg}\n"
    end
end


# Represents an update message. Can be both send and recieved.
class UpdateMessage

    ORIGIN_TYPE = [:IGP, :EGP, :UNK]

    def initialize(network, netmask, localpref, self_origin, aspath, origin)
        @network = network
        @netmask = netmask
        @localpref = localpref
        @self_origin = self_origin
        @aspath = aspath
        @origin = origin
    end

    attr_reader :network, :netmask

    # parse: Hash -> UpdateMessage
    # Craete update message from hashmap.
    def UpdateMessage.parse(msg)
        abort "ABORT: update message does not contain network\n" unless msg.key?(:network) 
        abort "ABORT: update message does not contain netmask\n" unless msg.key?(:netmask)
        abort "ABORT: update message does not contain localpref\n" unless msg.key?(:localpref)
        abort "ABORT: update message does not contain selfOrigin\n" unless msg.key?(:selfOrigin)
        abort "ABORT: update message does not contain ASPath\n" unless msg.key?(:ASPath)
        abort "ABORT: update message does not contain origin\n" unless msg.key?(:origin)
        
        network = IPv4.parse(msg[:network])
        netmask = IPv4.parse(msg[:netmask])
        localpref = msg[:localpref]
        self_origin = msg[:selfOrigin]
        aspath = msg[:ASPath]
        origin = msg[:origin].to_sym

        abort "ABORT: update message origin unrecognized\n" unless ORIGIN_TYPE.include?(origin)

        UpdateMessage.new(network, netmask, localpref, self_origin, aspath, origin)
    end

    # clone_with_asn: Int -> UpdateMessage
    # Create a new update message clone from self, with as path updated.
    def clone_with_asn(asn)
        aspath = @aspath.clone
        aspath.push(asn) unless aspath.include?(asn)
        UpdateMessage.new(@network, @netmask, @localpref, @self_origin, aspath, @origin)
    end

    # type: -> Symbol
    # Type of the message.
    def type
        :update
    end

    # subnet: -> IPAddr
    # Subnet using @network and @netmask.
    def subnet
        IPv4.subnet(@network, @netmask)
    end

    # to_route: -> Route
    # Route representation of the message.
    def to_route
        to_prejson
    end

    # to_prejson: -> Hash
    # Hash representation of the update message without subnet.
    def to_prejson
        {
            :network    => @network,
            :netmask    => @netmask,
            :localpref  => @localpref,
            :selfOrigin => @self_origin,
            :ASPath     => @aspath,
            :origin     => @origin
        }
    end

    # to_art: -> Hash
    # ASCII art representation of the update message.
    def to_art
        "\n\tnetwork:     #{@network}\n"\
          "\tnetmask:     #{@netmask}\n"\
          "\tlocalpref:   #{@localpref}\n"\
          "\tselfOrigin:  #{@self_origin}\n"\
          "\tasPath:      #{@aspath}\n"\
          "\torigin:      #{@origin}\n"
    end
end


# Represents a revoke message, can be both send and received.
class RevokeMessage 

    # @revoked_routes - list of routes that were asked to be revoked.
    def initialize(revoked_routes)
        @revoked_routes = revoked_routes
    end

    # parse: List[Hash] -> List[Hash]
    # Parse and validate revoked routes in the message.
    def RevokeMessage.parse(msg)
        revoked_routes = msg.map { |rt| 
            abort "ABORT: revoke message route does not contain network\n" unless rt.key?(:network)  
            abort "ABORT: revoke message route does not contain netmask\n" unless rt.key?(:netmask)

            network = IPv4.parse(rt[:network])
            netmask = IPv4.parse(rt[:netmask])

            { :network => network, :netmask => netmask }
        }
        RevokeMessage.new(revoked_routes)        
    end

    # type: -> Symbol
    # Type of the message.
    def type
        :revoke
    end

    # to_routes: -> List[Hash]
    # Returns list of revoked routes.
    def to_routes
        @revoked_routes
    end

    # to_prejson: -> List[Hash]
    # Returns list of revoked routes.
    def to_prejson
        @revoked_routes
    end

    # to_art: -> String
    # ASCII art representation of the revoke message.
    def to_art
        "\n" + @revoked_routes.map { |route|
            "\tnetwork: #{route[:network]} netmask: #{route[:netmask]}"
        }.join("\n")
    end
end


# Represents a data message, our router does not care about content.
class DataMessage

    def initialize(data)
        @data = data
    end

    # parse: Hash -> DumpMessage
    # We do not check the data msg.
    def DataMessage.parse(msg)
        DataMessage.new(msg)
    end

    # type: -> Symbol
    # Type of the message.
    def type
        :data
    end

    # to_prejson: -> Any
    # Returns data, we do not know anything about.
    def to_prejson
        @data
    end

    # to_art: -> String
    # ASCII art representation of the data message.
    def to_art
        "#{@data.slice(0, 10)}..."
    end
end


# Represents a dump message. Can only be received.
class DumpMessage

    # parse: Hash -> DumpMessage
    # Given hashmap has to be empty.
    def DumpMessage.parse(msg)
        abort "ABORT: dump message msg field not empty" unless msg.nil? || msg.empty?
        DumpMessage.new
    end

    # type: -> Symbol
    # Type of the message.
    def type
        :dump
    end

    # to_prejson: -> Hash
    # Returns empty hashmap.
    def to_prejson
        {}
    end

    # to_art: -> String
    # ASCII art representation of the dump message.
    def to_art
        "---"
    end
end


# Represents a message with forwarding table. Can only be send.
class TableMessage

    # @routes: List[Hash]
    def initialize(routes)
        @routes = routes
    end

    # type: -> Symbol
    # Type of the message.
    def type
        :table
    end

    # to_prejson: -> List[Hash]
    # Returns list of routes.
    def to_prejson
        @routes
    end

    # to_art: -> String
    # ASCII art representation of the table message.
    def to_art
        @routes.map { |route|
            "\tnetwork: #{route[:network]} netmask: #{route[:netmask]}"
        }.join("\n")
    end
end


# Represents a no route message, can only be send.
class NoRouteMessage

    # type: -> Symbol
    # Type of the message.
    def type
        :"no route"
    end

    # to_prejson: -> Hash
    # Returns empty hashmap.
    def to_prejson
        {}
    end

    # to_art: -> String
    # ASCII art representation of the no_route message.
    def to_art
        "---"
    end
end
