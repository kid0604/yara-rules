import "pe"

rule tuawktso_7685
{
	meta:
		description = "Files - file tuawktso.vbe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2022-02-01"
		hash1 = "1411250eb56c55e274fbcf0741bbd3b5c917167d153779c7d8041ab2627ef95f"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "* mP_5z" fullword ascii
		$s2 = "44:HD:\\C" fullword ascii
		$s3 = "zoT.tid" fullword ascii
		$s4 = "dwmcoM<" fullword ascii
		$s5 = "1iHBuSER:" fullword ascii
		$s6 = "78NLog.j" fullword ascii
		$s7 = "-FtP4p" fullword ascii
		$s8 = "x<d%[ * " fullword ascii
		$s9 = "O2f+  " fullword ascii
		$s10 = "- wir2" fullword ascii
		$s11 = "+ \"z?}xn$" fullword ascii
		$s12 = "+ $Vigb" fullword ascii
		$s13 = "# W}7k" fullword ascii
		$s14 = "# N)M)9" fullword ascii
		$s15 = "?uE- dO" fullword ascii
		$s16 = "W_* 32" fullword ascii
		$s17 = ">v9+ H" fullword ascii
		$s18 = "tUg$* h" fullword ascii
		$s19 = "`\"*- M" fullword ascii
		$s20 = "b^D$ -L" fullword ascii

	condition:
		uint16(0)==0xe0ee and filesize <12000KB and 8 of them
}
