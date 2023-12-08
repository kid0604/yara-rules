import "pe"

rule NsPackV13LiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects NsPack v1.3 by Liu Xing Ping"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 }

	condition:
		$a0 at pe.entry_point
}
