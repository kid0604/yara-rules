rule CN_Honker_WebScan_WebScan
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebScan.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a0b0e2422e0e9edb1aed6abb5d2e3d156b7c8204"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "wwwscan.exe" fullword wide
		$s2 = "WWWScan Gui" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}
