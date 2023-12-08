import "pe"

rule SEAAXEv22
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FC BC [2] 0E 1F A3 [2] E8 [2] A1 [2] 8B [3] 2B C3 8E C0 B1 03 D3 E3 8B CB BF [2] 8B F7 F3 A5 }

	condition:
		$a0 at pe.entry_point
}
