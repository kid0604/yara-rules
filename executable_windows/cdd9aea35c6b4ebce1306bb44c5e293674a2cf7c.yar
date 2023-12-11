import "pe"

rule NSPack3xLiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects NSPack3xLiuXingPing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 [2] FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01 }

	condition:
		$a0 at pe.entry_point
}
