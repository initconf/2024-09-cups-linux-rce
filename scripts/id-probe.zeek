module CUPS;

## This script extracts the URLs from the
## initial probe which is sent to 631/udp
## this initial probe has a callback URI which
## is where a vulnerable host will connect back

## We want to make sure callback_url is
## protocol, port and URI strings agnostic.
## eg. it flags the following all for URI, callbackIP, callback_port
## and callback protocols

## (i)   http://134.122.95.96:12345/printers/evilprinter "location_field" "info_field"
## (ii)  0000 0003 ipp://199.247.0.94:631/printers/test
## (iii) 0000 0003 http://www.badwebsite.com:9000/its/bad/website

export {
	global udp_631: event(uid: conn_id, hits: set[string]);

	redef enum Notice::Type += {
		# Sensitive POST seen
		Probe,
		ScannerIP,
		CallbackIP,
		CallbackDomain,
	};
}

redef udp_content_delivery_ports_orig += { [ 631/udp ] = T };

event CUPS::udp_631(uid: conn_id, hits: set[string])
	{
	local scanner = uid$orig_h;
	local callback: CallbackParts;

	local callback_ip_port: string;

	local msg = fmt ("Scanner: %s ", scanner);

	for ( link in hits )
	{
		msg += fmt ("link: %s ",link);

		if (domain_regex in link)
		{	local ph = extract_host (link);
			callback$port_ = extract_port (link);

			msg += fmt("callback_domain: %s, port: %s ", ph, callback$port_);

			NOTICE([ $note=CUPS::CallbackDomain, $id=uid, $src=scanner,
			$identifier=cat(scanner), $suppress_for=1hrs, $msg=msg ]);

		}
		else if (ip_regex in link)
		{
		 	callback$ip = extract_ip (link);
			callback$port_ = extract_port (link);
		}

			callback$url = link;
	}

	msg += fmt ("callback_ip: %s callback_port: %s", callback$ip, callback$port_);

	if ( callback$ip == scanner )
		{
			NOTICE([ $note=CUPS::Probe, $id=uid, $src=uid$orig_h,
			$identifier=cat( uid$orig_h), $suppress_for=1hrs, $msg=msg ]);
		}
	else if (callback$ip == 0.0.0.0)
		{
		# in this case we want to drop both ScannerIP and CallbackIP


		NOTICE([ $note=CUPS::ScannerIP, $id=uid, $src=uid$orig_h,
			$identifier=cat( uid$orig_h), $suppress_for=1hrs, $msg=msg ]);
		}

		NOTICE([ $note=CUPS::CallbackIP, $id=uid, $src=uid$orig_h,
			$identifier=cat( uid$orig_h), $suppress_for=1hrs, $msg=msg ]);


	event CUPS::build_intel(uid, callback);



	}

event udp_contents(u: connection, is_orig: bool, contents: string)
	{
	local hits: set[string];
	local orig = u$id$orig_h;



	if ( url_regex in contents )
		{
		hits = find_all_urls(contents);
		if ( |hits| > 0 )
		{
		@if ( Cluster::is_enabled() )
			Cluster::publish_hrw(Cluster::proxy_pool, orig, CUPS::udp_631, u$id, hits);
		@else
			event CUPS::udp_631(u$id, hits);
		@endif
		}
		}
	}

event udp_request(u: connection)
	{ }

event udp_reply(u: connection)
	{
	}
