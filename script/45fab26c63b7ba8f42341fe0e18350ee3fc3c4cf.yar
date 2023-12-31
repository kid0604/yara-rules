rule SUSP_FScan_Port_Scanner_Output_Jun23 : SCRIPT
{
	meta:
		description = "Detects output generated by the command line port scanner FScan"
		author = "Florian Roth"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		date = "2023-06-15"
		score = 70
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "[*] NetInfo:" ascii
		$s2 = ":443 open" ascii
		$s3 = "   [->]"

	condition:
		filesize <800KB and all of them
}
