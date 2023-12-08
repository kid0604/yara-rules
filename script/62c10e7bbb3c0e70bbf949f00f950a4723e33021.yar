rule Fierce2
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the Fierce2 domain scanner"
		date = "07/2014"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars,"

	condition:
		1 of them
}
