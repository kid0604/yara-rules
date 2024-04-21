rule WinRing0x64_sys
{
	meta:
		description = "files - file WinRing0x64.sys.bin"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
		date = "2022/07/10"
		hash1 = "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "d:\\hotproject\\winring0\\source\\dll\\sys\\lib\\amd64\\WinRing0.pdb" fullword ascii
		$s2 = "WinRing0.sys" fullword wide
		$s3 = "timestampinfo@globalsign.com0" fullword ascii
		$s4 = "\"GlobalSign Time Stamping Authority1+0)" fullword ascii
		$s5 = "\\DosDevices\\WinRing0_1_2_0" fullword wide
		$s6 = "OpenLibSys.org" fullword wide
		$s7 = ".http://crl.globalsign.net/RootSignPartners.crl0" fullword ascii
		$s8 = "Copyright (C) 2007-2008 OpenLibSys.org. All rights reserved." fullword wide
		$s9 = "1.2.0.5" fullword wide
		$s10 = " Microsoft Code Verification Root0" fullword ascii
		$s11 = "\\Device\\WinRing0_1_2_0" fullword wide
		$s12 = "WinRing0" fullword wide
		$s13 = "hiyohiyo@crystalmark.info0" fullword ascii
		$s14 = "GlobalSign1+0)" fullword ascii
		$s15 = "Noriyuki MIYAZAKI1(0&" fullword ascii
		$s16 = "The modified BSD license" fullword wide
		$s17 = "RootSign Partners CA1" fullword ascii
		$s18 = "\\/.gJ&" fullword ascii
		$s19 = "14012709" ascii
		$s20 = "140127110000Z0q1(0&" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and 8 of them
}
