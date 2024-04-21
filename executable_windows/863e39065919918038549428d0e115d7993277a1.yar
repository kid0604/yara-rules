rule case_19438_files_MalFiles_mswow86
{
	meta:
		description = "19438 - file mswow86.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "4d24b359176389301c14a92607b5c26b8490c41e7e3a2abbc87510d1376f4a87"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PCICL32.dll" fullword ascii
		$s2 = "client32.exe" fullword wide
		$s3 = "E:\\nsmsrc\\nsm\\1210\\1210\\client32\\Release\\client32.pdb" fullword ascii
		$s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
		$s5 = "7===>==>=>=>==>==>=>C" fullword ascii
		$s6 = "7>=>>>>>>=>>>>>>>>>>E" fullword ascii
		$s7 = "NetSupport Remote Control" fullword wide
		$s8 = "NetSupport Ltd0" fullword ascii
		$s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s10 = "NetSupport Ltd1" fullword ascii
		$s11 = "NetSupport Ltd" fullword wide
		$s12 = "!Copyright (c) 2015 NetSupport Ltd" fullword wide
		$s13 = "Copyright (c) 2015, NetSupport Ltd" fullword wide
		$s14 = "SLLQLOSL" fullword ascii
		$s15 = "Peterborough1" fullword ascii
		$s16 = "client32" fullword wide
		$s17 = "  </trustInfo>" fullword ascii
		$s18 = "_NSMClient32@8" fullword ascii
		$s19 = "TLDW*3S.*" fullword ascii
		$s20 = "NetSupport Client Application" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 8 of them
}
