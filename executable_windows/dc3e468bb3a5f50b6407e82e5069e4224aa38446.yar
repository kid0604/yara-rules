rule case_18190_1_beacon
{
	meta:
		description = "18190 - file 1.dll"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/"
		date = "2023-05-21"
		hash1 = "d3db55cd5677b176eb837a536b53ed8c5eabbfd68f64b88dd083dc9ce9ffb64e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "xtoofou674xh.dll" fullword ascii
		$s2 = "witnessed workroom authoritative bail advertise navy unseen co rival June quest manage detest predicate mainland smoke proudly s" ascii
		$s3 = " wig promise heal tangible reflections high elevate genus England wild chairman multitude jaws keyhole fairy rainy starts lease " ascii
		$s4 = "deplore word excellent consume left hers being tyre squeeze developed ardour fertility lucidly lion loft conquered grant restart" ascii
		$s5 = " Type Descriptor'" fullword ascii
		$s6 = "ic hairs species provision cocoa standard curtains discussed envelope books publicity interrupt sailor wilderness promising try " ascii
		$s7 = ".text$wlogeu" fullword ascii
		$s8 = "ch pensioner pub continual peaceable software beech indeed compromise assign comprehensive suitable disturbed oblige saw trying " ascii
		$s9 = "exual nails director filling great widen newspapers blank representative yell absorbed balcony normandy translate disc sympathet" ascii
		$s10 = " Class Hierarchy Descriptor'" fullword ascii
		$s11 = " Base Class Descriptor at (" fullword ascii
		$s12 = "fairly handsome bush " fullword ascii
		$s13 = "UXlsmX90" fullword ascii
		$s14 = " Complete Object Locator'" fullword ascii
		$s15 = "H)CpHcD$tL" fullword ascii
		$s16 = ".text$uogqsw" fullword ascii
		$s17 = ".text$heprqt" fullword ascii
		$s18 = ".text$euryob" fullword ascii
		$s19 = ".text$blaihb" fullword ascii
		$s20 = ".text$dffkjr" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 8 of them
}
