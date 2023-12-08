import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_AMSI_Bypass
{
	meta:
		author = "ditekSHen"
		description = "Detects AMSI bypass pattern"
		os = "windows"
		filetype = "script"

	strings:
		$v1_1 = "[Ref].Assembly.GetType(" ascii nocase
		$v1_2 = "System.Management.Automation.AmsiUtils" ascii
		$v1_3 = "GetField(" ascii nocase
		$v1_4 = "amsiInitFailed" ascii
		$v1_5 = "NonPublic,Static" ascii
		$v1_6 = "SetValue(" ascii nocase

	condition:
		5 of them and filesize <2000KB
}
