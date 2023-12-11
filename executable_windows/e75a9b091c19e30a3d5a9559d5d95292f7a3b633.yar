rule Impacket_Tools_psexec
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "27bb10569a872367ba1cfca3cf1c9b428422c82af7ab4c2728f501406461c364"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "impacket.examples.serviceinstall(" ascii
		$s2 = "spsexec" fullword ascii
		$s3 = "impacket.examples.remcomsvc(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and 2 of them )
}
