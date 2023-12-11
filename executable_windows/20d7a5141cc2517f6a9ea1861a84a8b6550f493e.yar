import "pe"

rule BopCryptv10
{
	meta:
		author = "malware-lu"
		description = "Detects BopCryptv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 BD [4] E8 [2] 00 00 }

	condition:
		$a0 at pe.entry_point
}
