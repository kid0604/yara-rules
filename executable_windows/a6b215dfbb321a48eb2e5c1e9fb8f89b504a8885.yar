import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCOM
{
	meta:
		description = "Detects Windows exceutables bypassing UAC using CMSTP COM interfaces. MITRE (T1218.003)"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$guid1 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide nocase
		$guid2 = "{3E000D72-A845-4CD9-BD83-80C07C3B881F}" ascii wide nocase
		$guid3 = "{BA126F01-2166-11D1-B1D0-00805FC1270E}" ascii wide nocase
		$s1 = "CoGetObject" fullword ascii wide
		$s2 = "Elevation:Administrator!new:" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and (1 of ($guid*) and 1 of ($s*))
}
