import "pe"

rule aPackv082
{
	meta:
		author = "malware-lu"
		description = "Detects aPackv082 malware based on specific byte sequence at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E 06 8C CB BA [2] 03 DA 8D [3] FC 33 F6 33 FF 48 4B 8E C0 8E DB }

	condition:
		$a0 at pe.entry_point
}
