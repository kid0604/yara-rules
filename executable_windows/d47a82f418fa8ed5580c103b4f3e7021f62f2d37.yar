import "pe"

rule WinZip32bitSFXv8xmodule
{
	meta:
		author = "malware-lu"
		description = "Detects 32-bit WinZip self-extracting module version 8.x"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 FF 15 [3] 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 [4] FF 15 }

	condition:
		$a0 at pe.entry_point
}
