import "pe"

rule UPX072
{
	meta:
		author = "malware-lu"
		description = "Detects UPX packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E }

	condition:
		$a0 at pe.entry_point
}
