rule Waterbear_11_Jun17
{
	meta:
		description = "Detects malware from Operation Waterbear"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/L9g9eR"
		date = "2017-06-23"
		hash1 = "b046b2e2569636c2fc3683a0da8cfad25ff47bc304145be0f282a969c7397ae8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "/Pages/%u.asp" fullword wide
		$s2 = "NVIDIA Corporation." fullword wide
		$s3 = "tqxbLc|fP_{eOY{eOX{eO" fullword ascii
		$s4 = "Copyright (C) 2005" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
