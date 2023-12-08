import "pe"

rule NsPacKNetLiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NsPacKNetLiuXingPing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 BB 01 47 65 74 53 79 73 74 65 6D 49 6E 66 6F 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 5E 00 5F 43 6F 72 [3] 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C }

	condition:
		$a0
}
