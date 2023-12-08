import "pe"

rule NeoLitev20_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects NeoLitev20_alt_1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 [28] 4E 65 6F 4C 69 74 65 }

	condition:
		$a0 at pe.entry_point
}
