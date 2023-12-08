import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_B64_Artifacts
{
	meta:
		author = "ditekSHen"
		description = "Detects executables embedding bas64-encoded APIs, command lines, registry keys, etc."
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA" ascii wide
		$s2 = "L2Mgc2NodGFza3MgL2" ascii wide
		$s3 = "QW1zaVNjYW5CdWZmZXI" ascii wide
		$s4 = "VmlydHVhbFByb3RlY3Q" ascii wide

	condition:
		uint16(0)==0x5a4d and 2 of them
}
