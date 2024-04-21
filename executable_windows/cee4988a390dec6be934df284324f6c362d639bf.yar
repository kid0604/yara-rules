rule smss_exe
{
	meta:
		description = "files - file smss.exe.bin"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
		date = "2022/07/10"
		hash1 = "d3c3f529a09203a839b41cd461cc561494b432d810041d71d41a66ee7d285d69"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "mCFoCRYPT32.dll" fullword ascii
		$s2 = "gPSAPI.DLL" fullword ascii
		$s3 = "www.STAR.com" fullword wide
		$s4 = "4;#pMVkWTSAPI32.dll" fullword ascii
		$s5 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii
		$s6 = "dYDT.Gtm" fullword ascii
		$s7 = "|PgGeT~^" fullword ascii
		$s8 = "* IiJ)" fullword ascii
		$s9 = "{DllB8qq" fullword ascii
		$s10 = "tfaqbjk" fullword ascii
		$s11 = "nrvgzgl" fullword ascii
		$s12 = "      <!--The ID below indicates application support for Windows 10 -->" fullword ascii
		$s13 = "5n:\\Tk" fullword ascii
		$s14 = "  </compatibility>" fullword ascii
		$s15 = "HHp.JOW" fullword ascii
		$s16 = "      <!--The ID below indicates application support for Windows 8 -->" fullword ascii
		$s17 = "      <!--The ID below indicates application support for Windows 7 -->" fullword ascii
		$s18 = "Wr:\\D;" fullword ascii
		$s19 = "px:\"M$" fullword ascii
		$s20 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <23000KB and 8 of them
}
