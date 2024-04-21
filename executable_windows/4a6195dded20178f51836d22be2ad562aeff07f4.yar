import "pe"

rule wmyvpa_7685
{
	meta:
		description = "Files - file wmyvpa.sae"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2022-02-01"
		hash1 = "3d913a4ba5c4f7810ec6b418d7a07b6207b60e740dde8aed3e2df9ddf1caab27"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "spfX.hRN<" fullword ascii
		$s2 = "wJriR>EOODA[.tIM" fullword ascii
		$s3 = "5v:\\VAL" fullword ascii
		$s4 = "K6U:\"&" fullword ascii
		$s5 = "%v,.IlZ\\" fullword ascii
		$s6 = "\\/kX>%n -" fullword ascii
		$s7 = "!Dllqj" fullword ascii
		$s8 = "&ZvM* " fullword ascii
		$s9 = "AU8]+ " fullword ascii
		$s10 = "- vt>h" fullword ascii
		$s11 = "+ u4hRI" fullword ascii
		$s12 = "ToX- P" fullword ascii
		$s13 = "S!G+ u" fullword ascii
		$s14 = "y 9-* " fullword ascii
		$s15 = "nl}* J" fullword ascii
		$s16 = "t /Y Fo" fullword ascii
		$s17 = "O^w- F" fullword ascii
		$s18 = "N -Vw'" fullword ascii
		$s19 = "hVHjzI4" fullword ascii
		$s20 = "ujrejn8" fullword ascii

	condition:
		uint16(0)==0xd3c2 and filesize <12000KB and 8 of them
}
