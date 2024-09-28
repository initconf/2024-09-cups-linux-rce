module CUPS;

## This script extracts the URLs from the
## initial probe which is sent to 631/udp
## this initial probe has a callback URI which
## is where a vulnerable host will connect back

## We want to make sure callback_url is
## protocol, port and URI strings agnostic.
## eg. it flags the following all for URI, callbackIP, callback_port
## and callback protocols

## (i) http://134.122.95.96:12345/printers/evilprinter "location_field" "info_field"
## (ii) 0000 0003 ipp://199.247.0.94:631/printers/test

export {
	global udp_631: event(uid: conn_id, hits: set[string]);

	redef enum Notice::Type += {
		# Sensitive POST seen
		Probe,
		ScannerIP,
		CallbackIP,
	};
}

redef udp_content_delivery_ports_orig += { [ 631/udp ] = T };

event udp_631(uid: conn_id, hits: set[string])
	{
	local scanner = uid$orig_h;
	local callback_ip_port: string;
	local callback_ip: addr;
	local callback_port: port;
	local callback_url: string;

	for ( link in hits )
		{
		callback_url = link;
		callback_ip_port = split_string(link, /\//)[2];
		callback_ip = to_addr(split_string(callback_ip_port, /:/)[0]);
		callback_port = to_port(fmt("%s/tcp", split_string(callback_ip_port,/:/)[1]));
		}

	local msg = fmt("link %s, callback_url: %s, callback_ip: %s, port: %s", link,
	    callback_url, callback_ip, callback_port);

	if ( callback_ip == scanner )
		{
		NOTICE([ $note=CUPS::Probe, $id=uid, $src=uid$orig_h,
			$identifier=cat( uid$orig_h), $suppress_for=1hrs, $msg=msg ]);
		}
	else
		{
		# in this case we want to drop both ScannerIP and CallbackIP

		NOTICE([ $note=CUPS::ScannerIP, $id=uid, $src=uid$orig_h,
			$identifier=cat( uid$orig_h), $suppress_for=1hrs, $msg=msg ]);

		NOTICE([ $note=CUPS::CallbackIP, $id=uid, $src=callback_ip,
			$identifier=cat( callback_ip), $suppress_for=1hrs, $msg=msg ]);
		}
	}

event udp_contents(u: connection, is_orig: bool, contents: string)
	{
	local hits: set[string];
	local orig = u$id$orig_h;

	if ( url in contents )
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
