import "pe"

rule PEncryptv31
{
	meta:
		author = "malware-lu"
		description = "Detects PEncryptv31 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 [3] 00 F0 0F C6 }

	condition:
		$a0 at pe.entry_point
}
