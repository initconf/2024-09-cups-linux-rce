module CUPS;

@load-sigs ../scripts/cups.sig

export {

redef enum Notice::Type += {
        SourceList,
};

redef Signatures::actions += {
        ["cups-rce-attempt"] = Signatures::SIG_ALARM_PER_ORIG,
	};

}

export {

global CUPS::cups_sig_match: event(orig: addr, msg: string);
global expire_cups_scanner: function(t: table[addr] of string, idx: addr): interval &redef;
global cups_scanner: table[addr] of string  &create_expire=0 secs &expire_func=expire_cups_scanner ;

}

hook Notice::policy(n: Notice::Info)
{
  if ( n$note == CUPS::Attempt)
        {
            add n$actions[Notice::ACTION_DROP];
        }
}

function expire_cups_scanner(t: table[addr] of string, idx: addr): interval
{

        local _msg = fmt ("%s", t[idx]);
       	NOTICE([$note=CUPS::Attempt, $src=idx, $msg=fmt("CUPS : %s - Sources : [%s]", idx, _msg), $identifier=cat (idx), $suppress_for=30 mins ]);

        return 0 secs ;
}

event signature_match(state: signature_state, msg: string, data: string)
{
    local resp = state$conn$id$resp_h ;
    local orig = state$conn$id$orig_h;

    if (/cups-rce-attempt/ in state$sig_id)
    {

	msg = fmt ("%s [%s]", msg, data);

	@if ( Cluster::is_enabled())
		    Cluster::publish_hrw(Cluster::proxy_pool, orig, CUPS::cups_sig_match,orig, msg );
	@else
		    event CUPS::cups_sig_match(orig, msg);
	@endif
    }
}

event CUPS::cups_sig_match (orig: addr, msg: string)
{
if (orig !in cups_scanner)
	cups_scanner[orig] = fmt ("%s", msg);
}
