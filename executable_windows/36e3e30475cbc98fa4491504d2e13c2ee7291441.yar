import "pe"

rule PcSharev40
{
	meta:
		author = "malware-lu"
		description = "Detects PcSharev40 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 90 34 40 00 68 B6 28 40 00 64 A1 }

	condition:
		$a0 at pe.entry_point
}
