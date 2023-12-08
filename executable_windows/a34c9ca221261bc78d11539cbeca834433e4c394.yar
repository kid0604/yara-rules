import "pe"

rule PEtitev21
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PEtitev21 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 6A ?? 68 [4] 64 FF 35 [4] 64 89 25 [4] 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}
