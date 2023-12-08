import "pe"

rule Xtreme_Sep17_3
{
	meta:
		description = "Detects XTREME sample analyzed in September 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-09-27"
		hash1 = "f540a4cac716438da0c1c7b31661abf35136ea69b963e8f16846b96f8fd63dde"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "Keylogg" fullword ascii
		$s4 = "XTREME" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and all of them )
}
