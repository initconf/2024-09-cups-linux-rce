module CUPS;

# although we've added embedded domains to Intel framework
# lets still watch here too

export {
                redef enum Notice::Type += {
                        HostileDomainLookup,
                };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=10
{
        #if (query in cups_callback_domains)
        #{
        #         NOTICE([$note=CUPS::HostileDomainLookup,
        #                        $conn=c,
        #                        $msg=fmt("CUPS Hostile domain seen %s=%s [%s]",c$id$orig_h, c$id$resp_h, query ),
        #                        $identifier=c$uid]);
        #}
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
{
    #if (ans$query in cups_callback_domains)
    #{
#@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )
#        #event CUPS::cups_new(cups_domains[ans$query]);
#        Broker::publish(Cluster::manager_topic, CUPS::cups_new, cups_domains[ans$query]);
#@endif
    #}

}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
{
    #if (ans$query in cups_domains)
    #{
    #    add cups_attack[c$id$orig_h]$callback_domains[ans$query];

#@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )
#    #event CUPS::cups_new(cups_domains[ans$query]);
#    Broker::publish(Cluster::manager_topic, CUPS::cups_new, cups_domains[ans$query]);
#@endif
    #}

}

