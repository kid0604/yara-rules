import "pe"

rule AppEncryptorSilentTeam
{
	meta:
		author = "malware-lu"
		description = "Detects the AppEncryptorSilentTeam malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 1F 1F 40 00 B9 7B 09 00 00 8D BD 67 1F 40 00 8B F7 AC }

	condition:
		$a0 at pe.entry_point
}
