rule Impacket_Tools_wmiexec
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "19544863758341fe7276c59d85f4aa17094045621ca9c98f8a9e7307c290bad4"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "bwmiexec.exe.manifest" fullword ascii
		$s2 = "swmiexec" fullword ascii
		$s3 = "\\yzHPlU=QA" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and 2 of them )
}
