import "pe"

rule MALWARE_Linux_GobRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects GobRAT"
		os = "linux"
		filetype = "executable"

	strings:
		$x1 = "BotList" ascii
		$x2 = "BotCount" ascii
		$x3 = "/etc/services/zone/bot.log" ascii
		$x4 = "aaa.com/bbb/me" ascii
		$s1 = "encoding/gob." ascii
		$s2 = ".GetMacAddress" ascii
		$s3 = ".IpString2Uint32" ascii
		$s4 = ".RegisterLogFile" ascii
		$s5 = ".UniqueAppendString" ascii
		$s6 = ".NewDaemon" ascii
		$s7 = ".SimpleCommand" ascii

	condition:
		uint16(0)==0x457f and (3 of ($x*) or (2 of ($x*) and 3 of ($s*)) or (1 of ($x*) and 5 of ($s*)) or all of ($s*))
}
