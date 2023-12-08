rule Impacket_Tools_secretsdump
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "47afa5fd954190df825924c55112e65fd8ed0f7e1d6fd403ede5209623534d7d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ssecretsdump" fullword ascii
		$s2 = "impacket.ese(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
