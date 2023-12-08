import "pe"

rule PrivateexeProtectorV18SetiSoftTeam
{
	meta:
		author = "malware-lu"
		description = "Yara rule for Privateexe Protector V18 by SetiSoftTeam"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 [4] 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
		$a0
}
