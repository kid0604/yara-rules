import "pe"

rule StealthPEv11
{
	meta:
		author = "malware-lu"
		description = "Detects StealthPEv11 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BA [3] 00 FF E2 BA [3] 00 B8 [4] 89 02 83 C2 03 B8 [4] 89 02 83 C2 FD FF E2 }

	condition:
		$a0 at pe.entry_point
}
