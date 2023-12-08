import "pe"

rule NeoLitev200
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NeoLitev200 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B 44 24 04 23 05 [4] 50 E8 [4] 83 C4 04 FE 05 [4] 0B C0 74 }

	condition:
		$a0 at pe.entry_point
}
