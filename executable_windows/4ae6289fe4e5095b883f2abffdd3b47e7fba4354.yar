rule Impacket_Tools_goldenPac
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "4f7fad0676d3c3d2d89e8d4e74b6ec40af731b1ddf5499a0b81fc3b1cd797ee3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "impacket.examples.serviceinstall(" ascii
		$s2 = "bgoldenPac.exe" fullword ascii
		$s3 = "json.scanner(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
