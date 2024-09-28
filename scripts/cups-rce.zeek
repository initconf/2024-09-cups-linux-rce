module CUPS;

redef Site::local_nets += { 128.3.0.0 / 16, 131.243.0.0 / 16, 198.128.0.0 / 16,
    0.0.0.0 / 1 };

export {
	redef enum Notice::Type += {
		# Sensitive POST seen
		Callback,
		Exploit,
		POST,
	};

	global url = /print|http:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+\/printers\/[a-zA-Z0-9]+|printers\/evilprinter|printers/;

	global cups_rce_notices: event(c: connection, method: string,
	    unescaped_URI: string);
}

event http_request(c: connection, method: string, original_URI: string,
    unescaped_URI: string, version: string) &priority=3
	{
	local orig = c$id$orig_h;

	if ( orig in Site::local_nets && method == "POST" && url in unescaped_URI )
		{
@if ( Cluster::is_enabled() )
		Cluster::publish_hrw(Cluster::proxy_pool, orig, CUPS::cups_rce_notices, c,
		    method, unescaped_URI);
@else
		event CUPS::cups_rce_notices(c, method, unescaped_URI);
@endif
		}
	}

event cups_rce_notices(c: connection, method: string, unescaped_URI: string)
	{
	local orig = c$id$orig_h;
	local p = split_string_all(cat(c$id$resp_p), /\//);

	local callback_url = fmt("%s:%s%s", c$id$resp_h, p[0], unescaped_URI);

	if ( orig in Site::local_nets && method == "POST" && url in callback_url )
		{
		NOTICE([ $note=Callback, $conn=c, $src=c$id$resp_h, $identifier=cat(
		    c$id$orig_h), $suppress_for=1hrs, $msg=fmt(
		    "URI: %s->%s:%s%s", c$id$orig_h, c$id$resp_h, p[0],
		    unescaped_URI) ]);
		}

	# For future stuff......
	if ( orig !in Site::local_nets && method == "POST" && url in unescaped_URI )
		{
		NOTICE([ $note=POST, $conn=c, $src=c$id$resp_h, $identifier=cat(c$id$orig_h),
		    $suppress_for=1hrs, $msg=fmt("URI: %s->%s:%s%s",
		    c$id$orig_h, c$id$resp_h, p[0], unescaped_URI) ]);
		}
	}
