module CUPS;

@load frameworks/intel/seen
@load frameworks/intel/do_notice

global already_seen_callbackip: set[addr] &create_expire=1 mins &backend=Broker::MEMORY;

export {
		redef enum Notice::Type += {
			CallBackIP,
			CallBack,
		} ;
}

event CUPS::build_intel (cid: conn_id, payload: CallbackParts)
{

    local a_item: Intel::Item ;

    # 1. Intel::ADDR - malware callback IPs
    if (payload?$ip)
    {
		a_item = [$indicator=fmt("%s", payload$ip),
					$indicator_type = Intel::ADDR,
					$meta = [$source = "cupsScript", $desc="Scanning IP Address", $do_notice=T] ];

		Intel::insert(a_item);

		if (cid$orig_h !in already_seen_callbackip)
		{
				NOTICE([$note=CallBackIP, $id=cid, $src=payload$ip,
					$msg=fmt("Callback IP [%s] seen from ip %s with payload of [%s]", payload$ip,  cid$orig_h, payload),
					$identifier=cat(cid), $suppress_for=1 day]);

			add already_seen_callbackip [cid$orig_h];
    	}
    }

    # 2. Intel::URL - sensitive_URL
    a_item = [$indicator=fmt("%s", payload$url), $indicator_type = Intel::URL,
                $meta = [$source = "cupsScript", $desc="URL of cups callback", $do_notice=T] ];

    Intel::insert(a_item);

    # 3 Intel::DOMAIN : If stem is a domain name
    if (payload?$domain)
    {
    a_item = [$indicator=fmt("%s", payload$domain), $indicator_type =
            Intel::DOMAIN, $meta = [$source = "cupsScript", $desc="DOMAIN of cups callback", $do_notice=T] ];

    Intel::insert(a_item);

    }


#    # 4. Watch callback IP+port
#    local a: ip_port = [$ip=payload$ip, $p=payload$port_] ;
#
#    if (a !in track_callback)
#    {
#        track_callback[a]=cid;
#        @if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )
#            Broker::publish(Cluster::manager_topic, CUPS::cups_new, payload$ip, payload$port_, cid);
#        @endif
#    }

}
