import "pe"
import "math"

rule APT_APT29_NOBELIUM_LNK_NV_Link_May21_2
{
	meta:
		description = "Detects NV Link as used by NOBELIUM group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "RegisterOCX BOOM" ascii wide
		$s2 = "cmd.exe /c start BOOM.exe" ascii wide

	condition:
		filesize <5000KB and 1 of them
}
