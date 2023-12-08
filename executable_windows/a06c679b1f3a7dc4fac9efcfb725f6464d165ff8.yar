import "pe"
import "math"

rule FscanRule2
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "onmlkji" fullword ascii
		$s2 = "pqrstu" fullword ascii
		$s3 = "aGVycywgYW5" fullword ascii
		$s4 = "U3ByaW5nQmxhZGU+" fullword ascii
		$s5 = "MGFiY2RlZ" fullword ascii
		$s6 = "YXBhY2hlL" fullword ascii
		$s7 = "LjgzODQxNDMv" fullword ascii
		$s8 = "ACLITEMP" fullword ascii
		$s9 = "gethped" fullword ascii
		$s10 = "bsddlln" fullword ascii
		$s11 = "5c%: && '!''%" fullword ascii
		$s12 = "IQtY:\\\\" fullword ascii
		$s13 = "999!!!!" fullword ascii
		$s14 = "\\2345\\." fullword ascii
		$s15 = "*$xoLR:\\" fullword ascii
		$s16 = "cceu:\"pt" fullword ascii
		$s17 = ",getL0og" fullword ascii
		$s18 = "%\"(5;-1," fullword ascii
		$s19 = "* |iaH" fullword ascii
		$s20 = "\";476837" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30000KB and 8 of them
}
