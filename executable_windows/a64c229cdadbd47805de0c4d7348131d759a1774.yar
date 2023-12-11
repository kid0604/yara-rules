rule EquationGroup_Toolset_Apr17_mstcp32_DXGHLP16_tdip
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "26215bc56dc31d2466d72f1f4e1b6388e62606e9949bc41c28968fcb9a9d60a6"
		hash2 = "fcfb56fa79d2383d34c471ef439314edc2239d632a880aa2de3cea430f6b5665"
		hash3 = "a5ec4d102d802ada7c5083af53fd9d3c9b5aa83be9de58dbb4fac7876faf6d29"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
		$s2 = "\\DosDevices\\%ws" fullword wide
		$s3 = "\\Device\\%ws_%ws" fullword wide
		$s4 = "sys\\mstcp32.dbg" fullword ascii
		$s5 = "%ws%03d%ws%wZ" fullword wide
		$s6 = "TCP/IP driver" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 4 of them )
}
