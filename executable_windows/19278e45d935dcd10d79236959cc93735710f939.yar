import "pe"

rule PrivateEXEProtector20SetiSoft
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting PrivateEXEProtector20SetiSoft malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 89 [2] 38 00 00 00 8B ?? 00 00 00 00 81 [5] 89 ?? 00 00 00 00 81 ?? 04 00 00 00 81 ?? 04 00 00 00 81 ?? 00 00 00 00 0F 85 D6 FF FF FF }

	condition:
		$a0
}
