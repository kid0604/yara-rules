import "pe"

rule APT_APT41_POISONPLUG_2
{
	meta:
		description = "Detects APT41 malware POISONPLUG"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		date = "2019-08-07"
		score = 70
		hash1 = "0055dfaccc952c99b1171ce431a02abfce5c6f8fb5dc39e4019b624a7d03bfcb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ma_lockdown_service.dll" fullword wide
		$s2 = "acbde.dll" fullword ascii
		$s3 = "MA lockdown Service" fullword wide
		$s4 = "McAfee Agent" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <11000KB and all of them
}
