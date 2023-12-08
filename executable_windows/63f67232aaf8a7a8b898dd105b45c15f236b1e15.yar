import "pe"

rule PEEncryptv40bJunkCode
{
	meta:
		author = "malware-lu"
		description = "Detects PEEncryptv40b malware with junk code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 66 [2] 00 66 83 ?? 00 }

	condition:
		$a0 at pe.entry_point
}
