import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_PE_ResourceTuner
{
	meta:
		author = "ditekSHen"
		description = "Detects executables with modified PE resources using the unpaid version of Resource Tuner"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Modified by an unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)" fullword wide

	condition:
		uint16(0)==0x5a4d and all of them
}
