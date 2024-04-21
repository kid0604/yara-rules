rule case_18543_eightc11812d_65fd_48ee_b650_296122a21067_zip
{
	meta:
		description = "18543 - file 8c11812d-65fd-48ee-b650-296122a21067.zip"
		author = "The DFIR Report via yarGen Rule Generator"
		reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
		date = "2023-08-28"
		hash1 = "be604dc018712b1b1a0802f4ec5a35b29aab839f86343fc4b6f2cb784d58f901"
		os = "windows,linux,macos,ios,android"
		filetype = "compressed"

	strings:
		$s1 = "OkskyF6" fullword ascii
		$s2 = "^Z* n~!" fullword ascii
		$s3 = "eanT0<-" fullword ascii
		$s4 = "_TULbx4j%`A" fullword ascii
		$s5 = "knDK^bE" fullword ascii
		$s6 = "yGsP!C" fullword ascii
		$s7 = ")tFFmt[d" fullword ascii
		$s8 = "uepeV1a-Ud" fullword ascii
		$s9 = "V`jtvX!" fullword ascii
		$s10 = "WYzqO=h" fullword ascii
		$s11 = "RRZDrM," fullword ascii
		$s12 = "msPBA|N" fullword ascii
		$s13 = "document-35068.isoUT" fullword ascii
		$s14 = "XuUgLiM" fullword ascii
		$s15 = "GFyM<]a" fullword ascii
		$s16 = "QjgMjS\\" fullword ascii
		$s17 = "fHqb3FJq= " fullword ascii
		$s18 = "Ndsfif" fullword ascii
		$s19 = "\\n9F8m" fullword ascii
		$s20 = "wZxzh5" fullword ascii

	condition:
		uint16(0)==0x4b50 and filesize <700KB and 8 of them
}
