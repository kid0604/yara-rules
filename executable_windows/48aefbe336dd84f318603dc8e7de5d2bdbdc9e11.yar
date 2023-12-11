import "pe"

rule MALWARE_Win_DarkComet
{
	meta:
		author = "ditekSHen"
		description = "Detects DarkComet"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s, ClassID: %s" ascii
		$s2 = "%s, ProgID: \"%s\"" ascii
		$s3 = "#KCMDDC51#" ascii
		$s4 = "#BOT#VisitUrl" ascii
		$s5 = "#BOT#OpenUrl" ascii
		$s6 = "#BOT#Ping" ascii
		$s7 = "#BOT#RunPrompt" ascii
		$s8 = "#BOT#CloseServer" ascii
		$s9 = "#BOT#SvrUninstall" ascii
		$s10 = "#BOT#URLUpdate" ascii
		$s11 = "#BOT#URLDownload" ascii
		$s12 = /BTRESULT(Close|Download|HTTP|Mass|Open|Ping\|Respond|Run|Syn|UDP|Uninstall\|uninstall|Update|Visit)/ ascii
		$s13 = "dclogs\\" fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
