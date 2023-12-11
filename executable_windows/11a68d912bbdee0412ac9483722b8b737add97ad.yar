rule CN_Honker_hxdef100
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file hxdef100.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bf30ccc565ac40073b867d4c7f5c33c6bc1920d6"
		os = "windows"
		filetype = "executable"

	strings:
		$s6 = "BACKDOORSHELL" fullword ascii
		$s15 = "%tmpdir%" fullword ascii
		$s16 = "%cmddir%" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
