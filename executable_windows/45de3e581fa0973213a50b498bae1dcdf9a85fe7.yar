import "pe"
import "math"

rule APT_APT29_NOBELIUM_Malware_May21_4
{
	meta:
		description = "Detects malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		hash1 = "3b94cc71c325f9068105b9e7d5c9667b1de2bde85b7abc5b29ff649fd54715c4"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "KM.FileSystem.dll" ascii fullword
		$op1 = { 80 3d 50 6b 04 10 00 0f 85 96 00 00 00 33 c0 40 b9 48 6b 04 10 87 01 33 db 89 5d fc }
		$op2 = { c3 33 c0 b9 7c 6f 04 10 40 87 01 c3 8b ff 55 }
		$op3 = { 8d 4d f4 e8 53 ff ff ff 68 d0 22 01 10 8d 45 f4 50 e8 d8 05 00 00 cc 8b 41 04 }
		$xc1 = { 2E 64 6C 6C 00 00 00 00 41 53 4B 4F 44 00 00 00
               53 75 63 63 65 73 73 }

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and ($xc1 or 3 of them )
}
