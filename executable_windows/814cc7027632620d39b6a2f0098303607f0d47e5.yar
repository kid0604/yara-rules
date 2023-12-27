rule RaccoonStealerv2
{
	meta:
		author = "RussianPanda"
		date = "04/17/2023"
		description = "Detects the latest unpacked/unobfuscated build 2.1.0-4"
		os = "windows"
		filetype = "executable"

	strings:
		$pattern1 = {B9 ?? ?? ?? 00 E8 ?? ?? ?? 00 ?? ?? 89 45 E8}
		$pattern2 = {68 ?? ?? ?? 00 ?? 68 01 00 1F 00}
		$pattern3 = {68 ?? ?? ?? 00 ?? ?? 68 01 00 1F 00 FF 15 64 ?? ?? 00}
		$m1 = {68 ?? ?? ?? 00 ?? 00 68 01 00 1f 00 ff 15 64 ?? ?? 00}
		$m2 = {68 ?? ?? ?? 00 ?? 68 01 00 1f 00 ff 15 64 ?? ?? 00}

	condition:
		2 of ($pattern*) and uint16(0)==0x5A4D and 1 of ($m*) and uint32( uint32(0x3C))==0x00004550 and filesize <200KB
}
