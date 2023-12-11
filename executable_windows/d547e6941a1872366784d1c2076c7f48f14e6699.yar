import "math"
import "pe"

rule FscanRule14
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 14"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "eempndnpy" fullword ascii
		$s2 = "fedcba" ascii
		$s3 = "aGVycywgYW5" fullword ascii
		$s4 = " YXNzd2Q=" fullword ascii
		$s5 = "0YmhmL21qb2wvZXBk" fullword ascii
		$s6 = "ZDUiOnRydWV9e" fullword ascii
		$s7 = "UDUDUD" fullword ascii
		$s8 = "cm9vdDpyb" fullword ascii
		$s9 = "irunbcd" fullword ascii
		$s10 = "4,-./0" fullword ascii
		$s11 = "IQtY:\\\\" fullword ascii
		$s12 = "\\2345\\." fullword ascii
		$s13 = "bsddll" fullword ascii
		$s14 = "NTLMDSS" fullword ascii
		$s15 = ",getL0og" fullword ascii
		$s16 = "%\"(5;-1," fullword ascii
		$s17 = "\";476837" fullword ascii
		$s18 = "Slogj+!" fullword ascii
		$s19 = "2!0-3&023" fullword ascii
		$s20 = ",[$2222 (" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <14000KB and 8 of them
}
