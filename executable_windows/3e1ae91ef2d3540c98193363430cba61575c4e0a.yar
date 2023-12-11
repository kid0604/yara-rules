rule CN_Honker_shell_brute_tool
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file shell_brute_tool.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f6903a15453698c35dce841e4d09c542f9480f01"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "http://24hack.com/xyadmin.asp" fullword ascii
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
