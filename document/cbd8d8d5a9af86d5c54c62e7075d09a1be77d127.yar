rule rtf_cve2017_11882_alt_1 : malicious exploit cve_2017_1182
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
		$headers = { 31 63 30 30 30 30 30 30  30 32 30 30 ?? ?? ?? ??
                     61 39 30 30 30 30 30 30  ?? ?? ?? ?? ?? ?? ?? ??
                     ?? ?? ?? ?? ?? ?? ?? ??  ?? ?? ?? ?? ?? ?? ?? ??
                     ?? ?? ?? ?? ?? ?? ?? ??  30 33 30 31 30 31 30 33
                     ?? ?? }
		$font = { 30 61 30 31 30 38 35 61  35 61 }
		$winexec = { 31 32 30 63 34 33 30 30 }

	condition:
		all of them and @font>@headers and @winexec==@font+((5+44)*2)
}
