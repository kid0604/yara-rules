import "pe"

rule NeoLitev10
{
	meta:
		author = "malware-lu"
		description = "Detects NeoLitev10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B 44 24 04 8D 54 24 FC 23 05 [4] E8 [4] FF 35 [4] 50 FF 25 }

	condition:
		$a0 at pe.entry_point
}
