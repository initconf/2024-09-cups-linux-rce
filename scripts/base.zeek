module CUPS;

export {

const url_regex = /^(https|ipp|http)?:\/\/([a-z0-9A-Z]+(:[a-zA-Z0-9]+)?@)?[-a-z0-9A-Z\-]+(\.[-a-z0-9A-Z\-]+)*((:[0-9]+)?)(\/[a-zA-Z0-9;:\/\.\-_+%~?&amp;@=#\(\)]*)?/;

}

# Extracts URLs discovered in arbitrary text.
function find_all_urls(s: string): string_set
	{
	return find_all(s, url_regex);
	}


# function takes a URL as input and returns the fqdn
#function extract_host(url: string): string
#	{
#	#local parts = split_string(url, /\/|\?/);
#	#return gsub(parts[2],/\.$/,"");
#
#	local host = "";
#	local domain_regex: pattern =
#	    /\/\/[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}\/?/;
#	local domain = find_all(url, domain_regex);
#
#	for ( d in domain )
#		{
#		host = gsub(d, /\/|\.$/, "");
#		break;
#		}
#
#	return host;
#	}
#
#
#
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
