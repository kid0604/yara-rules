rule file_ex_exe
{
	meta:
		description = "files - file ex.exe.bin"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
		date = "2022/07/10"
		hash1 = "428d06c889b17d5f95f9df952fc13b1cdd8ef520c51e2abff2f9192aa78a4b24"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "d:\\Projects\\WinRAR\\rar\\build\\unrar32\\Release\\UnRAR.pdb" fullword ascii
		$s2 = "rar.log" fullword wide
		$s3 = "      <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
		$s4 = "  processorArchitecture=\"*\"" fullword ascii
		$s5 = "%c%c%c%c%c%c%c" fullword wide
		$s6 = "  version=\"1.0.0.0\"" fullword ascii
		$s7 = "%12ls: RAR %ls(v%d) -m%d -md=%d%s" fullword wide
		$s8 = "  hp[password]  " fullword wide
		$s9 = " %s - " fullword wide
		$s10 = "yyyymmddhhmmss" fullword wide
		$s11 = "--------  %2d %s %d, " fullword wide
		$s12 = " Type Descriptor'" fullword ascii
		$s13 = "\\$\\3|$4" fullword ascii
		$s14 = "      processorArchitecture=\"*\"" fullword ascii
		$s15 = " constructor or from DllMain." fullword ascii
		$s16 = "----------- ---------  -------- -----  ----" fullword wide
		$s17 = "----------- ---------  -------- ----- -------- -----  --------  ----" fullword wide
		$s18 = "%-20s - " fullword wide
		$s19 = "      publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
		$s20 = "      version=\"6.0.0.0\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 8 of them
}
