rule Impacket_Tools_wmipersist
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "2527fff1a3c780f6a757f13a8912278a417aea84295af1abfa4666572bbbf086"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "swmipersist" fullword ascii
		$s2 = "\\yzHPlU=QA" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
