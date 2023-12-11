import "pe"

rule PEncryptv30
{
	meta:
		author = "malware-lu"
		description = "Detects PEncryptv30 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 8D B5 24 10 40 00 8B FE B9 0F 00 00 00 BB [4] AD 33 C3 E2 FA }

	condition:
		$a0 at pe.entry_point
}
