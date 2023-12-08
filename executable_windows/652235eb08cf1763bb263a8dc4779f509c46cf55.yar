rule CN_Honker_Cracker_SHELL
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SHELL.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c1dc349ff44a45712937a8a9518170da8d4ee656"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "http://127.0.0.1/error1.asp" fullword ascii
		$s2 = "password,PASSWORD,pass,PASS,Lpass,lpass,Password" fullword wide
		$s3 = "\\SHELL" wide
		$s4 = "WebBrowser1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
