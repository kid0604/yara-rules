import "pe"

rule MicroJoiner15coban2k
{
	meta:
		author = "malware-lu"
		description = "Detects the MicroJoiner15coban2k malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF }

	condition:
		$a0 at pe.entry_point
}
