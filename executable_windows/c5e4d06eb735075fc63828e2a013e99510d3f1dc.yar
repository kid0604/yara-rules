rule EnigmaPacker_Rare
{
	meta:
		description = "Detects an ENIGMA packed executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-04-27"
		score = 60
		hash1 = "77be6e80a4cfecaf50d94ee35ddc786ba1374f9fe50546f1a3382883cb14cec9"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "P.rel$oc$" fullword ascii
		$s2 = "ENIGMA" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <4000KB and all of them )
}
