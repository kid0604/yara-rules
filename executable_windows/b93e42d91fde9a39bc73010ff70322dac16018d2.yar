import "pe"

rule ProtectionPlusvxx
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting ProtectionPlusvxx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 60 29 C0 64 FF 30 E8 [4] 5D 83 ED 3C 89 E8 89 A5 14 [3] 2B 85 1C [3] 89 85 1C [3] 8D 85 27 03 [2] 50 8B ?? 85 C0 0F 85 C0 [3] 8D BD 5B 03 [2] 8D B5 43 03 [2] E8 DD [3] 89 85 1F 03 [2] 6A 40 68 ?? 10 [2] 8B 85 }

	condition:
		$a0 at pe.entry_point
}
