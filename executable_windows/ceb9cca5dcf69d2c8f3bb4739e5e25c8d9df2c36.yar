import "pe"

rule GlassesStrings : Glasses Family
{
	meta:
		description = "Strings used by Glasses"
		author = "Seth Hardy"
		last_modified = "2021-11-18"
		reference_file = "aaf262fde1738dbf0bb50213a9624cd6705ebcaeb06c5fcaf7e9f33695d3fc33"
		reference_url = "https://citizenlab.ca/2013/02/apt1s-glasses-watching-a-human-rights-organization/"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "thequickbrownfxjmpsvalzydg"
		$ = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0; %s.%s)"
		$ = "\" target=\"NewRef\"></a>"

	condition:
		all of them
}
