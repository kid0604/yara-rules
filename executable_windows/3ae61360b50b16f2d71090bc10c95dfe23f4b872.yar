rule CN_Honker_Pk_Pker
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Pker.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "631787f27f27c46f79e58e1accfcc9ecfb4d3a2f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "/msadc/..%5c..%5c..%5c..%5cwinnt/system32/cmd.exe" fullword wide
		$s2 = "msadc/..\\..\\..\\..\\winnt/system32/cmd.exe" fullword wide
		$s3 = "--Made by VerKey&Only_Guest&Bincker" fullword wide
		$s4 = ";APPLET;EMBED;FRAMESET;HEAD;NOFRAMES;NOSCRIPT;OBJECT;SCRIPT;STYLE;" fullword wide
		$s5 = " --Welcome to Www.Pker.In Made by V.K" fullword wide
		$s6 = "Report.dat" fullword wide
		$s7 = ".\\Report.dat" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 5 of them
}
