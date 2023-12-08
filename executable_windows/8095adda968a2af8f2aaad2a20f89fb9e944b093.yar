import "math"
import "pe"

rule FscanRule15
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 15"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "onmlkji" fullword ascii
		$s2 = "LjgzODQxNDM" fullword ascii
		$s3 = "MGFiY2RlZ" fullword ascii
		$s4 = "XjEkfCxOE" fullword ascii
		$s5 = "YXBhY2hlL" fullword ascii
		$s6 = "aGVycywgYW5m" fullword ascii
		$s7 = "circrsy" fullword ascii
		$s8 = "RHR0cHM6Ly93" fullword ascii
		$s9 = "bE0kNSMAE" fullword ascii
		$s10 = "fsieye" fullword ascii
		$s11 = "ECSHSfFHRSHSE.SUb" fullword ascii
		$s12 = "HV -v >O" fullword ascii
		$s13 = "B.CmWftp." fullword ascii
		$s14 = "'57.4;2\\-" fullword ascii
		$s15 = "seuevexeyeze{e|e}e~e" fullword ascii
		$s16 = ",h1,p=,r=- -j" fullword ascii
		$s17 = "2!0-3&023" fullword ascii
		$s18 = "* m\\9P" fullword ascii
		$s19 = ".g4CIRCLEDj" fullword ascii
		$s20 = "* ::}A" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <14000KB and 8 of them
}
