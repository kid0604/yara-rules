import "pe"
import "math"

rule APT_APT29_NOBELIUM_NativeZone_Loader_May21_1
{
	meta:
		description = "Detects NativeZone loader as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		date = "2021-05-27"
		score = 85
		hash1 = "136f4083b67bc8dc999eb15bb83042aeb01791fc0b20b5683af6b4ddcf0bbc7d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\SystemCertificates\\Lib\\CertPKIProvider.dll" ascii
		$s2 = "rundll32.exe %s %s" ascii fullword
		$s3 = "eglGetConfigs" ascii fullword
		$op1 = { 80 3d 74 8c 01 10 00 0f 85 96 00 00 00 33 c0 40 b9 6c 8c 01 10 87 01 33 db 89 5d fc }
		$op2 = { 8b 46 18 e9 30 ff ff ff 90 87 2f 00 10 90 2f 00 10 }
		$op3 = { e8 14 dd ff ff 8b f1 80 3d 74 8c 01 10 00 0f 85 96 00 00 00 33 c0 40 b9 6c 8c 01 10 87 01 }

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 3 of them or 4 of them
}
