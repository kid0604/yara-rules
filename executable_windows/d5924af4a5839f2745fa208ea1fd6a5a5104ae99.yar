import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EnableSMBv1
{
	meta:
		author = "ditekSHen"
		description = "Detects binaries with PowerShell command enabling SMBv1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 1 of them
}
