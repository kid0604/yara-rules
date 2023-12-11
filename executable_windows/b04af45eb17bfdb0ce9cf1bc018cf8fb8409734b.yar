import "pe"
import "math"

rule APT_APT29_NOBELIUM_Stageless_Loader_May21_2
{
	meta:
		description = "Detects stageless loader as used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		hash1 = "a4f1f09a2b9bc87de90891da6c0fca28e2f88fd67034648060cef9862af9a3bf"
		hash2 = "c4ff632696ec6e406388e1d42421b3cd3b5f79dcb2df67e2022d961d5f5a9e78"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "DLL_stageless.dll" ascii fullword
		$s1 = "c:\\users\\devuser\\documents" ascii fullword nocase
		$s2 = "VisualServiceComponent" ascii fullword
		$s3 = "CheckUpdteFrameJavaCurrentVersion" ascii fullword
		$op1 = { a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 68 d8 d4 00 10 57 a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 }
		$op2 = { ff d6 33 05 00 ?0 0? 10 68 d8 d4 00 10 57 a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 68 e8 d4 00 10 }

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 2 of them or 3 of them
}
