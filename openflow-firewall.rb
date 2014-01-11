class MyController < Controller
    
    ###################
    # read rule from configuration file
    ##################
    def start
        @rules = []
        read_rules ARGV[1]
    end

    ###################
    #send rule to switch
    #for every pkt that enters the switch, send it to controller
    #let icmp and arp packets pass directly
    ###################
    def switch_ready datapath_id
        dl_type_arp = 0x0806
        dl_type_ipv4 = 0x0800
        #allow arp and icmp packets
        #please fill up the following blank ****** user input from here ******
        arp_match = Match.new( :dl_type => dl_type_arp )
        send_flow_mod_add( datapath_id,
            :match => arp_match,
            :actions => ActionOutput.new( OFPP_FLOOD )
        )
        #ICMP flows both ways
        icmp_match_1 = Match.new( 
            :in_port => 1,
            :dl_type => dl_type_ipv4,
            :nw_proto => 1 )
        send_flow_mod_add( datapath_id,
            :match => icmp_match_1,
            :actions => ActionOutput.new( 2 )
        )
        icmp_match_2 = Match.new( 
            :in_port => 2,
            :dl_type => dl_type_ipv4,
            :nw_proto => 1 )
        send_flow_mod_add( datapath_id,
            :match => icmp_match_2,
            :actions => ActionOutput.new( 1 )
        )



    end

    #######################
    # if packet is allowed in the configure file, add a rule to the switch
    # that also allows future packets going through the reverse path
    # else deny it (drop it)
    ######################
    def packet_in datapath_id, message
        match = ExactMatch.from( message )
        action, log = lookup_rules( datapath_id, match )
        info "action=#{ action }, datapath_id=#{ datapath_id.to_hex }, message={#{ match.to_s }}" if log
        if action == :allow
            #set rules in the switch
            #please fill up the following blank ****** user input from here ******
            send_flow_mod_add( datapath_id,
                :match => match,
                :idle_timeout => 300,
                :hard_timeout => 300,
                :actions => ActionOutput.new( (match.in_port == 1)? 2 : 1 )
            )
            #set rules in the switch for reverse path
            #please fill up the following blank ****** user input from here ******
            # reverse flow has the same attributes, but with source/destination
            # swapped
            reverse_match = Match.new(
                :in_port => (match.in_port == 1)? 2 : 1,
                :dl_src => match.dl_dst, # swapping source and dest
                :dl_dst => match.dl_src, # MAC addresses
                :dl_type => match.dl_type,
                :dl_vlan => match.dl_vlan,
                :dl_vlan_pcp => match.dl_vlan_pcp,
                :nw_tos => match.nw_tos,
                :nw_proto => match.nw_proto,
                :nw_src => match.nw_dst, # swapping source and dest
                :nw_dst => match.nw_src, # IP addresses
                :tp_src => match.tp_dst, # swapping source and dest
                :tp_dst => match.tp_src # TCP ports
            )
            info "reverse flow: {#{ reverse_match.to_s }}"
            send_flow_mod_add( datapath_id,
                :match => reverse_match,
                :idle_timeout => 300,
                :hard_timeout => 300,
                :actions => ActionOutput.new( (reverse_match.in_port == 1)? 2 : 1 )
            )
        else 
            #set drop rule in the switch
            #please fill up the following blank ****** user input from here ******
            send_flow_mod_add( datapath_id,
                :match => match,
                :idle_timeout => 300,
                :hard_timeout => 300,
            )
        end
    end
    
    ###################################################
    private
    ###################################################

    def read_rules file_name
        dl_type_arp = 0x0806
        dl_type_ipv4 = 0x0800
        
        #allow all arp packets 
        allow :dl_type => dl_type_arp
        #allow all icmp packets
        allow :dl_type => dl_type_ipv4, :nw_proto => 1

        File.open(file_name, "r").each_line do |line|
            puts line
            line = line.strip.split(' ')
            if line[0] == ''
                continue
            end
            myhash = {:dl_type => dl_type_ipv4, :nw_proto => 6, :log => true}
            if line[0] != 'any'
                myhash.merge!( :nw_src => line[0] )
            end
            if line[1] != 'any'
                myhash.merge!( :tp_src => Integer( line[1] ) )
            end
            if line[2] != 'any'
                myhash.merge!( :nw_dst => line[2] )
            end
            if line[3] != 'any'
                myhash.merge!( :tp_dst => Integer( line[3] ) )
            end
            allow myhash
        end
        block :log => true
    end

    def allow hash = {}
        add_rule :allow, hash
    end
    def block hash = {}
            add_rule :block, hash
    end
    def add_rule action, hash
            datapath_id = hash.key?( :datapath_id ) && hash.delete( :datapath_id ) || nil
            log = hash.key?( :log ) && hash.delete( :log ) || false
        rule = Struct.new( :action, :datapath_id, :match, :log )
        @rules << rule.new( action, datapath_id, Match.new( hash ), log )
        #print "rule added: " + ","+
        #    hash[:dl_type].to_s() + ","+ 
        #    hash[:nw_src]+ ","+
        #    hash[:tp_src].to_s()+ ","+
        #    hash[:nw_dst]+ ","+
        #    hash[:tp_dst].to_s()+ 
        #    ", Action is: "+ action.to_s() + "\n"
    end
    def lookup_rules datapath_id, match
        action = :block # default action
        log = false
        @rules.each do | each |
            if !each.datapath_id.nil? && datapath_id != each.datapath_id
                next
            end
            if each.match.compare( match )
                action = each.action
                log = each.log
                break
            end
        end
            return action, log
    end
end

