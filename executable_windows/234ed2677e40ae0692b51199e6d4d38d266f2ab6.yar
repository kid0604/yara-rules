import "pe"

rule EncryptPE12003518WFS
{
	meta:
		author = "malware-lu"
		description = "Detects encrypted PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 }

	condition:
		$a0 at pe.entry_point
}
