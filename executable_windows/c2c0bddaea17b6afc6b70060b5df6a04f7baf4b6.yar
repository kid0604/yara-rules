rule Impacket_Tools_netview
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "ab909f8082c2d04f73d8be8f4c2640a5582294306dffdcc85e83a39d20c49ed6"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "impacket.dcerpc.v5.wkst(" ascii
		$s2 = "dummy_threading(" ascii
		$s3 = "snetview" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
