import "pe"

rule NsPackV14LiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects NsPack v1.4 by Liu Xing Ping"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }

	condition:
		$a0 at pe.entry_point
}
