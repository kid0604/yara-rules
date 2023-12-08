import "pe"

rule VirogenCryptv075
{
	meta:
		author = "malware-lu"
		description = "Detects VirogenCryptv075 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01 }

	condition:
		$a0 at pe.entry_point
}
