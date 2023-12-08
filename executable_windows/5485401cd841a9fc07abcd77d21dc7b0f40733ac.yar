rule Impacket_Tools_esentutl
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "70d854953d3ebb2c252783a4a103ba0e596d6ab447f238af777fb37d2b64c0cd"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "impacket.ese(" ascii
		$s2 = "sesentutl" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <11000KB and all of them )
}
