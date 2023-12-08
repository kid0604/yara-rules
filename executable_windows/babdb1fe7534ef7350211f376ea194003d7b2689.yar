import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_DcRatBy
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing the string DcRatBy"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DcRatBy" ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
