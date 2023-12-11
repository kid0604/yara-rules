rule Impacket_Tools_wmiquery
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "202a1d149be35d96e491b0b65516f631f3486215f78526160cf262d8ae179094"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "swmiquery" fullword ascii
		$s2 = "\\yzHPlU=QA" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
