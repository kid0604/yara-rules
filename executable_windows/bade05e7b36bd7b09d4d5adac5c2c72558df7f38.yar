rule Impacket_Tools_atexec
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "337bd5858aba0380e16ee9a9d8f0b3f5bfc10056ced4e75901207166689fbedc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "batexec.exe.manifest" fullword ascii
		$s2 = "satexec" fullword ascii
		$s3 = "impacket.dcerpc" fullword ascii
		$s4 = "# CSZq" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and 3 of them )
}
