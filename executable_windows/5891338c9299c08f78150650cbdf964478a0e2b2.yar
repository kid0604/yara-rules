import "pe"
import "math"

rule FscanRule1
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "3c4c5c6c7c" ascii
		$s2 = "ze/processOp:ons7" fullword ascii
		$s3 = "sbGVjdGlU" fullword ascii
		$s4 = "LjgzODQxND" fullword ascii
		$s5 = "5c%: && '!''%'(" fullword ascii
		$s6 = "L21qb2wvZXBk" fullword ascii
		$s7 = "d0d1d2d3d5" ascii
		$s8 = "ransport" fullword ascii
		$s9 = "templaL" fullword ascii
		$s10 = "runbcdl" fullword ascii
		$s11 = "dxqp.USw" fullword ascii
		$s12 = "\\.2334\\" fullword ascii
		$s13 = "pgdll547" fullword ascii
		$s14 = "IDENTIF" fullword ascii
		$s15 = "THPINGPEPLUSPORTS" fullword ascii
		$s16 = "* YpINp" fullword ascii
		$s17 = "u^sYnRJgeT" fullword ascii
		$s18 = "%'W* -" fullword ascii
		$s19 = "* I!-," fullword ascii
		$s20 = "6c3a.5e78" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30000KB and 8 of them
}
