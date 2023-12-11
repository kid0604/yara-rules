import "pe"

rule Slingshot_APT_Spork_Downloader
{
	meta:
		description = "Detects malware from Slingshot APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/apt-slingshot/84312/"
		date = "2018-03-09"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Usage: spork -c IP:PORT" fullword ascii wide
		$s2 = "connect-back IP address and port number"

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them
}
