module CUPS;

@load-sigs ../scripts/cups.sig

export {
	redef enum Notice::Type += { SigMatch, };

	redef Signatures::actions += { [ "cups-rce-attempt" ] =
	    Signatures::SIG_ALARM_PER_ORIG,  };
}

export {
	global CUPS::cups_sig_match: event(state: signature_state, msg: string);
	global expire_cups_scanner: function(t: table[addr] of string, idx: addr)
	    : interval &redef;
	global cups_scanner: table[addr] of string &create_expire=0secs
	    &expire_func=expire_cups_scanner;
}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == CUPS::SigMatch )
		{
		add n$actions[Notice::ACTION_DROP];
		}
	}

function expire_cups_scanner(t: table[addr] of string, idx: addr): interval
	{
	return 0secs;
	}

event signature_match(state: signature_state, msg: string, data: string)
	{
	local resp = state$conn$id$resp_h;
	local orig = state$conn$id$orig_h;

	if ( /cups-rce-attempt/ in state$sig_id )
		{
		msg = fmt("%s [%s]", msg, data);

@if ( Cluster::is_enabled() )
		Cluster::publish_hrw(Cluster::proxy_pool, orig, CUPS::cups_sig_match, state,
		    msg);
@else
		event CUPS::cups_sig_match(state, msg);
@endif
		}
	}

event CUPS::cups_sig_match(state: signature_state, msg: string)
	{

	print fmt ("matched ... ");

	local orig = state$conn$id$orig_h;

	if ( orig !in cups_scanner )
		{
		cups_scanner[orig] = fmt("%s", msg);
		NOTICE([ $note=CUPS::SigMatch, $conn=state$conn, $src=orig, $msg=fmt(
		    "CUPS : %s - Sources : [%s]", orig, msg), $identifier=cat(
		    orig), $suppress_for=30mins ]);
		}
	}
