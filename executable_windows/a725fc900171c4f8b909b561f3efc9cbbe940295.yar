import "pe"

rule HPA
{
	meta:
		author = "malware-lu"
		description = "Detects HPA malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5E 8B D6 83 [2] 83 [2] 06 0E 1E 0E 1F 33 FF 8C D3 }

	condition:
		$a0 at pe.entry_point
}
