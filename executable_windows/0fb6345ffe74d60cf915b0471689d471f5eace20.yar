import "pe"

rule znmxbx_7685
{
	meta:
		description = "Files - file znmxbx.evj"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/"
		date = "2022-02-01"
		hash1 = "e510566244a899d6a427c1648e680a2310c170a5f25aff53b15d8de52ca11767"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "# /rL,;" fullword ascii
		$s2 = "* m?#;rE" fullword ascii
		$s3 = ">\\'{6|B{" fullword ascii
		$s4 = "36\\$'48`" fullword ascii
		$s5 = "&#$2\\&6&[" fullword ascii
		$s6 = "zduwzpa" fullword ascii
		$s7 = "CFwH}&.MWi " fullword ascii
		$s8 = "e72.bCZ<" fullword ascii
		$s9 = "*c:\"HK!\\" fullword ascii
		$s10 = "mBf:\"t~" fullword ascii
		$s11 = "7{R:\"O`" fullword ascii
		$s12 = "7SS.koK#" fullword ascii
		$s13 = "7lS od:\\" fullword ascii
		$s14 = "kMRWSyi$%D^b" fullword ascii
		$s15 = "Wkz=c:\\" fullword ascii
		$s16 = "1*l:\"L" fullword ascii
		$s17 = "GF8$d:\\T" fullword ascii
		$s18 = "i$\".N8spy" fullword ascii
		$s19 = "f4LOg@" fullword ascii
		$s20 = "XiRcwU" fullword ascii

	condition:
		uint16(0)==0x3888 and filesize <12000KB and 8 of them
}
