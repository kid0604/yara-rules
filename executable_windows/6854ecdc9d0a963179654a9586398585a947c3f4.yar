rule WindosShell_s1
{
	meta:
		description = "Detects simple Windows shell - file s1.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[ executing cmd.exe" fullword ascii
		$s2 = "[ simple remote shell for windows v1" fullword ascii
		$s3 = "-p <number>  Port number to use (default is 443)" fullword ascii
		$s4 = "usage: s1 <address> [options]" fullword ascii
		$s5 = "[ waiting for connections on %s" fullword ascii
		$s6 = "-l           Listen for incoming connections" fullword ascii
		$s7 = "[ connection from %s" fullword ascii
		$s8 = "[ %c%c requires parameter" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <150KB and 2 of them ) or (5 of them )
}
