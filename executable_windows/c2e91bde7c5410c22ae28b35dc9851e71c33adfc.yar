import "pe"

rule PrivateexeProtector20SetiSoftTeam
{
	meta:
		author = "malware-lu"
		description = "Detects Privateexe Protector 2.0 by SetiSoftTeam"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 [4] 00 00 00 00 00 00 }

	condition:
		$a0
}
