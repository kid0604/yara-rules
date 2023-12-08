rule Exploit_MS15_077_078 : Exploit
{
	meta:
		description = "MS15-078 / MS15-077 exploit - generic signature"
		author = "Florian Roth"
		reference = "https://code.google.com/p/google-security-research/issues/detail?id=473&can=1&start=200"
		date = "2015-07-21"
		hash1 = "18e3e840a5e5b75747d6b961fca66a670e3faef252aaa416a88488967b47ac1c"
		hash2 = "0b5dc030e73074b18b1959d1cf7177ff510dbc2a0ec2b8bb927936f59eb3d14d"
		hash3 = "fc609adef44b5c64de029b2b2cff22a6f36b6bdf9463c1bd320a522ed39de5d9"
		hash4 = "ad6bb982a1ecfe080baf0a2b27950f989c107949b1cf02b6e0907f1a568ece15"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "GDI32.DLL" fullword ascii
		$s2 = "atmfd.dll" fullword wide
		$s3 = "AddFontMemResourceEx" fullword ascii
		$s4 = "NamedEscape" fullword ascii
		$s5 = "CreateBitmap" fullword ascii
		$s6 = "DeleteObject" fullword ascii
		$op0 = { 83 45 e8 01 eb 07 c7 45 e8 }
		$op1 = { 8d 85 24 42 fb ff 89 04 24 e8 80 22 00 00 c7 45 }
		$op2 = { eb 54 8b 15 6c 00 4c 00 8d 85 24 42 fb ff 89 44 }
		$op3 = { 64 00 88 ff 84 03 70 03 }

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of ($s*) or all of ($op*)
}
