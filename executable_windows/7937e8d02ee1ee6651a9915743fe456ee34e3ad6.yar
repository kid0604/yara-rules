import "pe"

rule MALWARE_Win_GENIRCBot
{
	meta:
		author = "ditekSHen"
		description = "Detects generic IRCBots"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "@login" ascii nocase
		$s2 = "PRIVMSG" fullword ascii
		$s3 = "JOIN" fullword ascii
		$s4 = "PING :" fullword ascii
		$s5 = "NICK" fullword ascii
		$s6 = "USER" fullword ascii
		$x1 = "irc.danger.net" fullword ascii nocase
		$x2 = "evilBot" fullword ascii nocase
		$x3 = "#evilChannel" fullword ascii nocase

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or 2 of ($x*))
}
