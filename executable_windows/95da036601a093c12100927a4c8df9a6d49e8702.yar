import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_DotNetProcHook
{
	meta:
		author = "ditekSHen"
		description = "Detects executables with potential process hoocking"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "UnHook" fullword ascii
		$s2 = "SetHook" fullword ascii
		$s3 = "CallNextHook" fullword ascii
		$s4 = "_hook" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
