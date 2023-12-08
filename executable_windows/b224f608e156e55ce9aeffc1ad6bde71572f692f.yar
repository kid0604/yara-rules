rule CN_Honker_CoolScan_scan
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file scan.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e1c5fb6b9f4e92c4264c7bea7f5fba9a5335c328"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "User-agent:\\s{0,32}(huasai|huasai/1.0|\\*)" fullword ascii
		$s1 = "scan web.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <3680KB and all of them
}
