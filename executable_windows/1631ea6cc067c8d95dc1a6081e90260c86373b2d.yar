import "pe"
import "math"

rule APT_APT29_NOBELIUM_BoomBox_May21_1_alt_2
{
	meta:
		description = "Detects BoomBox malware as described in APT29 NOBELIUM report"
		author = "Florian Roth"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		date = "2021-05-27"
		modified = "2025-03-20"
		score = 85
		hash = "8199f309478e8ed3f03f75e7574a3e9bce09b4423bd7eb08bb5bff03af2b7c27"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "]::FromBase64String($" ascii wide
		$xa1 = "123do3y4r378o5t34onf7t3o573tfo73" ascii wide fullword
		$xa2 = "1233t04p7jn3n4rg" ascii wide fullword
		$s1 = "\\Release\\BOOM.pdb" ascii
		$s2 = "/files/upload" ascii
		$s3 = "/tmp/readme.pdf" ascii fullword
		$s4 = "/new/{0}" ascii fullword
		$s5 = "(&(objectClass=user)(objectCategory=person))"

	condition:
		( uint16(0)==0x5a4d or 1 of ($a*)) and (1 of ($x*) or 3 of ($s*))
}
