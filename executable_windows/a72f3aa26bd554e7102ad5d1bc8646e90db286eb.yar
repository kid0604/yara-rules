import "pe"

rule UPX050070
{
	meta:
		author = "malware-lu"
		description = "Detects UPX packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D }

	condition:
		$a0 at pe.entry_point
}
