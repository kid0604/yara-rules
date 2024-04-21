rule case_15184_FilesToHash_locker
{
	meta:
		description = "15184_ - file locker.dll"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/"
		date = "2022-11-28"
		hash1 = "6424b4983f83f477a5da846a1dc3e2565b7a7d88ae3f084f3d3884c43aec5df6"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "plugin.dll" fullword ascii
		$s2 = "oL$0fE" fullword ascii
		$s3 = "H9CPtgL9{@tafD9{8tZD" fullword ascii
		$s4 = "expand 32-byte k" fullword ascii
		$s5 = "oD$@fD" fullword ascii
		$s6 = "oF D3f0D3n4D3v8D3~<H" fullword ascii
		$s7 = "j]{7r]Y" fullword ascii
		$s8 = "EA>EmA" fullword ascii
		$s9 = "ol$0fE" fullword ascii
		$s10 = "S{L1I{" fullword ascii
		$s11 = "V32D!RT" fullword ascii
		$s12 = " A_A^_" fullword ascii
		$s13 = "v`L4~`g" fullword ascii
		$s14 = "9\\$8vsH" fullword ascii
		$s15 = "K:_Rich" fullword ascii
		$s16 = " A_A^A\\_^" fullword ascii
		$s17 = "tsf90u" fullword ascii
		$s18 = "9|$0vQ" fullword ascii
		$s19 = "K:_=:?^" fullword ascii
		$s20 = ":9o 49" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 8 of them
}
