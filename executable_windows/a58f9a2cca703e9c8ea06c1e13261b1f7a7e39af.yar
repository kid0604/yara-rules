import "pe"

rule WinZip32bitSFXv6xmodule
{
	meta:
		author = "malware-lu"
		description = "Detects 32-bit WinZip self-extracting module version 6.x"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FF 15 [3] 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 38 08 74 06 40 80 38 00 75 F6 80 38 00 74 01 40 33 C9 [4] FF 15 }

	condition:
		$a0 at pe.entry_point
}
