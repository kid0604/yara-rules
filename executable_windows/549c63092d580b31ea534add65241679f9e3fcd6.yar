import "pe"

rule CodeCryptv015b
{
	meta:
		author = "malware-lu"
		description = "Detects CodeCryptv015b malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 31 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

	condition:
		$a0 at pe.entry_point
}
