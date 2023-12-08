import "math"
import "pe"

rule FscanRule13
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 13"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cdefgi" fullword ascii
		$s2 = "aGVycywgYW5" fullword ascii
		$s3 = " YXNzd2Q=" fullword ascii
		$s4 = "=TT5uZnR0YmhmL21qb2wvZXB" fullword ascii
		$s5 = "sckddll" fullword ascii
		$s6 = "gethped" fullword ascii
		$s7 = "#yKey1keye\\s" fullword ascii
		$s8 = "100101" ascii
		$s9 = "templaL" fullword ascii
		$s10 = "prfaildmu" fullword ascii
		$s11 = "ddllnv" fullword ascii
		$s12 = "KHrp:\"" fullword ascii
		$s13 = "\\rr* -" fullword ascii
		$s14 = "HPINGPEPLUSPORTSR" fullword ascii
		$s15 = "Al.CmWftp.Ns" fullword ascii
		$s16 = "'\"7\"C\"" fullword ascii
		$s17 = "\"bGet2`,&Dtcx" fullword ascii
		$s18 = "seuevexeyeze{e|e}e~e" fullword ascii
		$s19 = "getL^OR" fullword ascii
		$s20 = "####4?7;####%)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20000KB and 7 of them
}
