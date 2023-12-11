rule Impacket_Tools_tracer
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "e300339058a885475f5952fb4e9faaa09bb6eac26757443017b281c46b03108b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "btk85.dll" fullword ascii
		$s2 = "btcl85.dll" fullword ascii
		$s3 = "xtk\\unsupported.tcl" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <21000KB and all of them )
}
