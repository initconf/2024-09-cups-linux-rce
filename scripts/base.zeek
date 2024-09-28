module CUPS;

export {

	#const url_regex = /^(http|ipp|https)?:\/\/([a-z0-9A-Z]+(:[a-zA-Z0-9]+)?@)?[-a-z0-9A-Z\-]+(\.[-a-z0-9A-Z\-]+)*((:[0-9]+)?)(\/[a-zA-Z0-9;:\/\.\-_+%~?&amp;@=#\(\)]*)?/;
	const url_regex = /(https?|ftp|ipp):\/\/[-a-zA-Z0-9+&@#\/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#\/%=~_|].*/ ;

  	global domain_regex = /[A-Za-z0-9]+([\-\.]{1}[A-Za-z0-9]+)*\.[a-zA-Z]{2,6}\/?[A-Za-z0-9]+/;
        global ip_regex = /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)|(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)|(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)|([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}/ ;

	 type CallbackParts: record {
                    url: string &default = "";
                    ip: addr &default=0.0.0.0;
                    port_: port &default=0/unknown;
                    domain: string &default ="";
                    };

	global cups_attack: table[addr] of cups_attack_mo ;
}

# Extracts URLs discovered in arbitrary text.
function find_all_urls(s: string): string_set
	{
	return find_all(s, url_regex);
	}

# function takes URL and returns IP
function extract_port (link: string): port
	{
	local callback_port = 0/unknown;
	local callback_ip_port = split_string(link, /\//)[2];
	callback_port = to_port(fmt("%s/tcp", split_string(callback_ip_port,/:/)[1]));

	return callback_port;
	}

# function takes URL and returns IP
function extract_ip (link: string): addr
	{

 	local callback_ip = 0.0.0.0 ;
	local callback_ip_port = split_string(link, /\//)[2];
	callback_ip = to_addr(split_string(callback_ip_port, /:/)[0]);

	return callback_ip;

	}


# function takes a URL as input and returns the fqdn
function extract_host(url: string): string
	{
	#local parts = split_string(url, /\/|\?/);
	#return gsub(parts[2],/\.$/,"");

	local host = "";
	#local domain_regex: pattern = /\/\/[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}\/?/;
	local domain = find_all(url, domain_regex);

	for ( d in domain )
		{
		host = gsub(d, /\/|\.$/, "");
		break;
		}

	return host;
	}



# # Extracts URLs discovered in arbitrary text without
# # the URL scheme included.
#function find_all_urls_without_scheme(s: string): string_set
#	{
#	local urls = find_all_urls(s);
#	local return_urls: set[string] = set();
#	for ( url in urls )
#		{
#		local no_scheme = sub(url, /^([a-zA-Z\-]{3,5})(:\/\/)/, "");
#		add return_urls[no_scheme];
#		}
#
#	return return_urls;
#	}
