import "pe"

rule WinZip32bit6x
{
	meta:
		author = "malware-lu"
		description = "Detects 32-bit WinZip executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FF 15 FC 81 40 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 }

	condition:
		$a0 at pe.entry_point
}
