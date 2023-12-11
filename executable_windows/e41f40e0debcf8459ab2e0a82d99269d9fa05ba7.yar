import "pe"

rule UPXv103v104
{
	meta:
		author = "malware-lu"
		description = "Detects UPX version 1.03 and 1.04 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }

	condition:
		$a0 at pe.entry_point
}
