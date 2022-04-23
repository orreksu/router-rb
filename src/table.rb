
# Represents forwarding table with history in the router.
class Table

    def initialize
        @updates = []
        @revokes = []
        @table = []
    end

    # public -----------------------------------------------------------------

    # update!: Packet -> Nil
    # Update the table in place with given packet.
    def update!(packet)
        @updates.push(packet)
        add_route!(packet.src.clone, packet.msg.clone)
    end

    # revoke!: Packet -> Nil
    # Revoke given packet from the table in place.
    def revoke!(packet)
        @revokes.push(packet)
        @table.clear
        valid_updates.each { |packet| add_route!(packet.src.clone, packet.msg.clone) }
    end

    # has_hop_to?: IPAddr -> Bool
    # Does this table has hop to given adress?
    def has_hop_to?(dst) 
        @table.any? { |route| route[:subnet].include?(dst) }
    end

    # get_hop_to: IPAddr -> IPAddr
    # Return hop to the given adress.
    # Note: does not check for invalidity, as should be used
    #       after has_hop_to?(dst) 
    def get_hop_to(dst)
        routes = @table.select { |route| route[:subnet].include?(dst) }
        best = routes.max { |a, b| better_route(a,b) }
        best[:hop]
    end

    # show: -> Nil
    # Print this as ASCII art.
    def show 
        puts to_art
    end

    # to_art: -> String
    # ASCII art representation of the table.
    def to_art
        routes = @table.map { |route|
            "  hop(#{route[:hop]}) --> network(#{route[:network]}), netmask(#{route[:netmask]})"
        }.join("\n")

        "TABLE\n"\
        "#{routes}\n\n"
    end

    # to_msg: -> TableMessage
    # TableMessage representation of the table.
    def to_msg
        TableMessage.new(routes)
    end

    private # ----------------------------------------------------------------

    # add_route!: IPAddr, UpdateMessage -> Unit
    # Add route specified by update message to the table in place.
    def add_route!(hop, msg)
        route = msg.to_route
        route[:hop] = hop
        route[:subnet] = msg.subnet
        @table.push(route)
        loop_aggregate!
        show if DEBUG
    end
    
    # aggregate!: -> Nil
    # Loop untill no more table entries can be aggregated.
    def loop_aggregate!
        loop do
            prev_table_length = @table.length
            try_aggregate_once!
            break if @table.length == prev_table_length
        end
    end

    # aggregate_once!: -> Nil
    # Aggregate any two entries in the table if possible.
    # Sorts table by hops, so most likely lower ips would be agregated first.
    # Aggregate happens only if two enties could be found by searching with aggr?
    def try_aggregate_once!

        # sort the table from smallest hop ip to largest
        @table.sort! { |ra, rb| ra[:hop] <=> rb[:hop] }

        # for each table entry try to find another entry that can be aggregate
        @table.each do |ra|

            # get aggregatable entry for ra
            rb = @table.bsearch { |rb| ra != rb && aggr?(ra, rb) }
            next if rb.nil?

            # aggregate ra and rb
            ra[:netmask] = ra[:netmask] << 1
            ra[:network] = ra[:network] & ra[:netmask]
            ra[:subnet] = IPv4.subnet(ra[:network], ra[:netmask])
            @table.delete(rb)
            break
        end
    end

    # aggr?: Route, Route -> Bool
    # Can we aggregate two given routes?
    def aggr?(ra, rb)
        same_hop?(ra, rb)   &&
        same_attrs?(ra, rb) &&   
        adjacent?(ra, rb)
    end

    # same_hop?: Route, Route -> Bool
    # Do two given routes have same hop?
    def same_hop?(ra, rb)
        ra[:hop] == rb[:hop]
    end

    # same_attrs?: Route, Route -> Bool
    # Do two given routes have the same attributes?
    def same_attrs?(ra, rb)
        ra[:localpref] == rb[:localpref] &&
        ra[:selfOrigin] == rb[:selfOrigin] &&
        ra[:ASPath] == rb[:ASPath] &&
        ra[:origin] == rb[:origin]
    end

    # adjacent?: Route, Route -> Bool
    # Are two given routes numerically adjecent?
    def adjacent?(ra, rb)
        return false if ra[:netmask] != rb[:netmask]

        mask = ra[:netmask] # = rb[:netmask]
        mask_leng = IPv4.prefix(mask)

        ra_net = ra[:network]
        ra_net_bits = IPv4.to_b(ra_net)

        rb_net = rb[:network]
        rb_net_bits = IPv4.to_b(rb_net)

        ra_net_bits.slice(0, mask_leng-1) == rb_net_bits.slice(0, mask_leng-1) and
        ra_net_bits[mask_leng-1] != rb_net_bits[mask_leng-1]
    end

    # valid_updates: -> List[Packet]
    # List of unrevoked (valid) updates.
    def valid_updates
        @updates.reject { |update| update_was_revoked?(update) }
    end

    # update_was_revoked?: Packet -> Bool
    # Was this update revoked by any of the revokes?
    def update_was_revoked?(update)
        @revokes.any? { |revoke| revoke_removes_update?(revoke, update) }
    end

    # revoke_removes_update?: Packet, Packet -> Bool
    # Does this revoke removes the given update?
    def revoke_removes_update?(revoke, update)
        revoke.src == update.src and 
        revoke.msg.to_routes.any? { |route| update_same_route?(update, route) }
    end

    # update_same_route?: Packet, Route -> Bool
    # Is given route same as the one specified by the packet?
    def update_same_route?(update, route)
        route[:network] == update.msg.network and
        route[:netmask] == update.msg.netmask
    end

    # better_route: -> -1 | 0 | 1
    # Starship operator to compare two given routes,
    # prefereence is given as described below.
    # Note: 1 -> a
    #      -1 -> b
    def better_route(a, b)

        # The path with longest prefix wins. If equal... 
        if a[:netmask] != b[:netmask]
            return a[:netmask] > b[:netmask] ? 1 : -1
        end

        # The path with the highest "localpref" wins. If equal... 
        if a[:localpref] != b[:localpref]
            return a[:localpref] > b[:localpref] ? 1 : -1
        end

        # The path with "selfOrigin" = true wins. If equal... 
        if a[:selfOrigin] != b[:selfOrigin]
            return a[:selfOrigin] ? 1 : -1
        end

        # The path with the shortest "ASPath" wins. If equal... 
        if a[:ASPath].length != b[:ASPath].length 
            return a[:ASPath].length < b[:ASPath].length ? 1 : -1
        end

        # The path with the best "origin" wins, were IGP > EGP > UNK. If equal... 
        if a[:origin] != b[:origin]
            return  1 if a[:origin] == :IGP
            return -1 if b[:origin] == :IGP
            return  1 if a[:origin] == :EGP
            return -1 if b[:origin] == :EGP
        end

        # The path from the neighbor router with the lowest IP address.
        if a[:hop] != b[:hop]
            return a[:hop] < b[:hop] ? 1 : -1
        end

        abort "We should not have identical routes in the table!\n"
    end

    # routes: -> List[Hash]
    # Return list of hashmaps from table, that specifies only
    # network, netmask, and hop.
    # Note: peer is named required by assignemnt for whatever reason...
    def routes 
        @table.map { |route|
            {
                :network    => route[:network],
                :netmask    => route[:netmask],
                :peer       => route[:hop]
            }
        }
    end
end