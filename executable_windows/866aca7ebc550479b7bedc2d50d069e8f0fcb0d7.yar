import "pe"

rule SDProtectorV11xRandyLi
{
	meta:
		author = "malware-lu"
		description = "Detects SDProtector V1.1x by Randy Li"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 88 88 88 08 64 A1 }

	condition:
		$a0 at pe.entry_point
}
