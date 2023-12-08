import "pe"

rule CodeCryptv0164
{
	meta:
		author = "malware-lu"
		description = "Detects CodeCryptv0164 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34 }

	condition:
		$a0 at pe.entry_point
}
