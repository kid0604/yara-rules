import "math"
import "pe"

rule APT_APT29_NOBELIUM_Malware_May21_3
{
	meta:
		description = "Detects malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		hash1 = "2a352380d61e89c89f03f4008044241a38751284995d000c73acf9cad38b989e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Win32Project1.dll" ascii fullword
		$op1 = { 59 c3 6a 08 68 70 5e 01 10 e8 d2 8c ff ff 8b 7d 08 8b c7 c1 f8 05 }
		$op2 = { 8d 4d f0 e8 c4 12 00 00 68 64 5b 01 10 8d 45 f0 c7 45 f0 6c 01 01 10 50 e8 ea 13 00 00 cc }
		$op4 = { 40 c3 8b 65 e8 e8 a6 86 ff ff cc 6a 0c 68 88 60 01 10 e8 b0 4d ff ff }
		$xc1 = { 25 73 25 73 00 00 00 00 2F 65 2C 20 00 00 00 00
               43 00 3A 00 5C 00 77 00 69 00 6E 00 64 00 6F 00
               77 00 73 00 5C 00 65 00 78 00 70 00 6C 00 6F 00
               72 00 65 00 72 00 2E 00 65 00 78 00 65 }

	condition:
		filesize <3000KB and ($xc1 or 3 of them )
}
