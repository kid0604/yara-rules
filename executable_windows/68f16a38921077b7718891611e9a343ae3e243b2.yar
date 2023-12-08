rule CN_Honker_wwwscan_gui
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wwwscan_gui.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "897b66a34c58621190cb88e9b2a2a90bf9b71a53"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii
		$s2 = "/eye2007Admin_login.aspx" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <280KB and all of them
}
