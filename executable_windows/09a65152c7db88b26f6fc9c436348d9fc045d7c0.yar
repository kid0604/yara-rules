import "math"
import "pe"

rule FscanRule10
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 10"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "aW5nQmxhZGU5c" fullword ascii
		$s2 = "LjgzODQxNDM" fullword ascii
		$s3 = "MGFiY2RlZ" fullword ascii
		$s4 = "aGVycywgYW5m" fullword ascii
		$s5 = "UDUDUD" fullword ascii
		$s6 = "pqrst<" fullword ascii
		$s7 = "templaLR" fullword ascii
		$s8 = "RHR0cHM6Ly93" fullword ascii
		$s9 = "221222" ascii
		$s10 = "=>?@AB" fullword ascii
		$s11 = "fprfaildmueat" fullword ascii
		$s12 = "bsddll" fullword ascii
		$s13 = " /y G)" fullword ascii
		$s14 = "252D /267A " fullword ascii
		$s15 = "$%&'()2!8@" fullword ascii
		$s16 = "ftpgE;gc gj0m" fullword ascii
		$s17 = "@>@5000@." fullword ascii
		$s18 = "Q[SlogVm%" fullword ascii
		$s19 = "$GrGet2k" fullword ascii
		$s20 = "[ /s R" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20000KB and 8 of them
}
