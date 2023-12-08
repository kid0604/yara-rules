import "pe"
import "math"

rule FscanRule3
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
		$s2 = "ize/processOp" fullword ascii
		$s3 = ".TGphdmEvdXR" fullword ascii
		$s4 = "LjgzODQxNDM" fullword ascii
		$s5 = "MGFiY2RlZ" fullword ascii
		$s6 = "gethped" fullword ascii
		$s7 = "CPRI * HTTP/2.0ZF" fullword ascii
		$s8 = "\\:W!!!!" fullword ascii
		$s9 = "333333i" fullword ascii
		$s10 = "templaL" fullword ascii
		$s11 = "U3ByaW5nQmxhZGU5" fullword ascii
		$s12 = "GEYe\\h" fullword ascii
		$s13 = "_/sys/kernel/mm/tf" fullword ascii
		$s14 = "retkey " fullword ascii
		$s15 = "4.3.3322!#6334" fullword ascii
		$s16 = "2!0-3&023" fullword ascii
		$s17 = "51`\"$$?." fullword ascii
		$s18 = "]@`@%3\\0" fullword ascii
		$s19 = "LoggyNF^" fullword ascii
		$s20 = "4*+,<'-''.4" fullword ascii

	condition:
		uint16(0)==0x457f and filesize <30000KB and 8 of them
}
