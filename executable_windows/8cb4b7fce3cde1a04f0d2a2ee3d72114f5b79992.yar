rule __case_5295_GAS
{
	meta:
		description = "5295 - file GAS.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-12"
		hash1 = "be13b8457e7d7b3838788098a8c2b05f78506aa985e0319b588f01c39ca91844"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "A privileged instruction was executed at address 0x00000000." fullword ascii
		$s2 = "Stack dump (SS:ESP)" fullword ascii
		$s3 = "!This is a Windows NT windowed executable" fullword ascii
		$s4 = "An illegal instruction was executed at address 0x00000000." fullword ascii
		$s5 = "ff.exe" fullword wide
		$s6 = "Open Watcom C/C++32 Run-Time system. Portions Copyright (C) Sybase, Inc. 1988-2002." fullword ascii
		$s7 = "openwatcom.org" fullword wide
		$s8 = "Open Watcom Dialog Editor" fullword wide
		$s9 = "A stack overflow was encountered at address 0x00000000." fullword ascii
		$s10 = "A fatal error is occured" fullword ascii
		$s11 = "An integer divide by zero was encountered at address 0x00000000." fullword ascii
		$s12 = "address 0x00000000 and" fullword ascii
		$s13 = "Open Watcom" fullword wide
		$s14 = "The instruction at 0x00000000 caused an invalid operation floating point" fullword ascii
		$s15 = "The instruction at 0x00000000 caused a denormal operand floating point" fullword ascii
		$s16 = "`.idata" fullword ascii
		$s17 = "xsJr~.~" fullword ascii
		$s18 = "iJJW3We" fullword ascii
		$s19 = "Rmih_O|" fullword ascii
		$s20 = "The instruction at 0x00000000 referenced memory " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
