rule Impacket_Tools_mmcexec
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "263a1655a94b7920531e123a8c9737428f2988bf58156c62408e192d4b2a63fc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "smmcexec" fullword ascii
		$s2 = "\\yzHPlU=QA" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <16000KB and all of them )
}
