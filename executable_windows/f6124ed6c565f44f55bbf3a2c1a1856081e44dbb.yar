import "pe"

rule NsPackV11LiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects NsPack v1.1 by Liu Xing Ping"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }

	condition:
		$a0 at pe.entry_point
}
