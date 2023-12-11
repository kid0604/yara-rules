import "pe"

rule MALWARE_Win_ZombieBoy
{
	meta:
		author = "ditekSHen"
		description = "Detects ZombieBoy Downloader"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ":\\Users\\ZombieBoy\\" ascii wide
		$s2 = "RookIE/1.0" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
