import "pe"

rule UPXScramblerRCv1x
{
	meta:
		author = "malware-lu"
		description = "Detects UPX Scrambler RCv1x"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 61 BE [4] 8D BE [4] 57 83 CD FF }

	condition:
		$a0 at pe.entry_point
}
