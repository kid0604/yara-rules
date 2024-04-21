rule yara_bluesky_ransomware
{
	meta:
		description = "file vmware.exe"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/"
		date = "2023-12-02"
		hash1 = "d4f4069b1c40a5b27ba0bc15c09dceb7035d054a022bb5d558850edfba0b9534"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "040<0G0#1+111;1A1I1" fullword ascii
		$s2 = "VWjPSP" fullword ascii
		$s3 = "040J0O0" fullword ascii
		$s4 = "4Y:)m^." fullword ascii
		$s5 = ":6:I:O:}:" fullword ascii
		$s6 = "5.6G6t6" fullword ascii
		$s7 = ";%;N;X;c;r;" fullword ascii
		$s8 = "747h7h8" fullword ascii
		$s9 = "8K8S8m8" fullword ascii
		$s10 = ";#;.;9;D;" fullword ascii
		$s11 = "6%6+6G8M8" fullword ascii
		$s12 = "0\"0&0,02060<0B0F0u0" fullword ascii
		$s13 = "hQSqQh" fullword ascii
		$s14 = "QVhNkO" fullword ascii
		$s15 = "?+?3?G?T?" fullword ascii
		$s16 = ":-;<;k;" fullword ascii
		$s17 = "1%212H2" fullword ascii
		$s18 = "h@pVxh=" fullword ascii
		$s19 = ">Gfm_E1:" fullword ascii
		$s20 = "'1]1e1m1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 8 of them
}
