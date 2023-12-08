import "pe"
import "math"

rule APT_APT29_NOBELIUM_BoomBox_May21_1
{
	meta:
		description = "Detects BoomBox malware as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		date = "2021-05-27"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$xa1 = "123do3y4r378o5t34onf7t3o573tfo73" ascii wide fullword
		$xa2 = "1233t04p7jn3n4rg" ascii wide fullword

	condition:
		1 of them
}
