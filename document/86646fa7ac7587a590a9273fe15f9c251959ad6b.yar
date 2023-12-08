rule rtf_cve2017_11882_ole : malicious exploit cve_2017_11882
{
	meta:
		author = "John Davison"
		description = "Attempts to identify the exploit CVE 2017 11882"
		reference = "https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about"
		sample = "51cf2a6c0c1a29abca9fd13cb22421da"
		score = 60
		os = "windows"
		filetype = "document"

	strings:
		$headers = { 1c 00 00 00 02 00 ?? ?? a9 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 01 01 03 ?? }
		$font = { 0a 01 08 5a 5a }
		$winexec = { 12 0c 43 00 }

	condition:
		all of them and @font>@headers and @winexec==@font+5+44
}
