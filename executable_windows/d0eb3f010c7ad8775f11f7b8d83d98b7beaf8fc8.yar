import "math"
import "pe"

rule APT_APT29_NOBELIUM_BoomBox_May21_2
{
	meta:
		description = "Detects BoomBox malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		hash1 = "0acb884f2f4cfa75b726cb8290b20328c8ddbcd49f95a1d761b7d131b95bafec"
		hash2 = "8199f309478e8ed3f03f75e7574a3e9bce09b4423bd7eb08bb5bff03af2b7c27"
		hash3 = "cf1d992f776421f72eabc31d5afc2f2067ae856f1c9c1d6dc643a67cb9349d8c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Microsoft\\NativeCache\\NativeCacheSvc.dll" wide
		$x2 = "\\NativeCacheSvc.dll _configNativeCache" wide
		$a1 = "/content.dropboxapi.com" wide fullword
		$s1 = "rundll32.exe {0} {1}" wide fullword
		$s2 = "\\\\CertPKIProvider.dll" wide
		$s3 = "/tmp/readme.pdf" wide
		$s4 = "temp/[^\"]*)\"" wide fullword
		$op1 = { 00 78 00 2d 00 41 00 50 00 49 00 2d 00 41 00 72 00 67 00 01 2f 4f 00 72 00 }
		$op2 = { 25 72 98 01 00 70 6f 34 00 00 0a 25 6f 35 00 00 0a 72 71 02 00 70 72 }
		$op3 = { 4d 05 20 00 12 80 91 04 20 01 08 0e 04 20 00 12 }

	condition:
		uint16(0)==0x5a4d and filesize <40KB and 3 of them or 4 of them
}
