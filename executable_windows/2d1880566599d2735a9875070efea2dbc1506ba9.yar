rule malware_TokyoX_RAT
{
	meta:
		description = "detect TokyoX RAT"
		author = "JPCERT/CC Incident Response Group"
		hash = "46bf7ca79cd21289081e518a7b3bc310bbfafc558eb3356b987319fec4d15939"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 74 6F 6B 79 6F 00 00 00 }
		$format1 = "%08lX%04lX%04lX%02lx%02lx%02lx%02lx%02lx%02lx%02lx%02lx"
		$format2 = "%d-%d-%d %d:%d:%d" wide
		$uniq_path = "C:\\Windows\\SysteSOFTWARE\\Microsoft\\Windows NT\\Cu"

	condition:
		($mz at 0 and all of ($format*)) or $uniq_path
}
