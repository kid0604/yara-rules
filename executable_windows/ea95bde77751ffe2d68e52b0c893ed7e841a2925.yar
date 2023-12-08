rule CN_Honker_T00ls_scanner
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls_scanner.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "70b04b910d82b32b90cd7f355a0e3e17dd260cb3"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "http://cn.bing.com/search?first=1&count=50&q=ip:" fullword wide
		$s17 = "Team:www.t00ls.net" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <330KB and all of them
}
