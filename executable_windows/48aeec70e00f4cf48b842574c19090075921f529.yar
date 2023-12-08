import "pe"
import "math"

rule APT_APT29_NOBELIUM_Malware_May21_2
{
	meta:
		description = "Detects malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		hash1 = "292e5b0a12fea4ff3fc02e1f98b7a370f88152ce71fe62670dd2f5edfaab2ff8"
		hash2 = "776014a63bf3cc7034bd5b6a9c36c75a930b59182fe232535bb7a305e539967b"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 48 03 c8 42 0f b6 04 21 88 03 0f b6 43 01 8b c8 83 e0 0f 48 83 e1 f0 48 03 c8 }
		$op2 = { 48 03 c8 42 0f b6 04 21 88 43 01 41 0f b6 c7 8b c8 83 e0 0f 48 83 e1 f0 48 03 c8 }
		$op3 = { 45 0f b6 43 ff 41 8b c2 99 44 88 03 41 0f b6 2b 83 e2 03 03 c2 40 88 6b 01 }

	condition:
		filesize <2200KB and all of them
}
