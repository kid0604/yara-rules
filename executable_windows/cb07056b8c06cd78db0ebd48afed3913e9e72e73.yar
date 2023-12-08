import "pe"

rule MAL_Trickbot_Oct19_1
{
	meta:
		description = "Detects Trickbot malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-10-02"
		hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
		hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
		hash3 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Celestor@hotmail.com" fullword ascii
		$s2 = "\\txtPassword" ascii
		$s14 = "Invalid Password, try again!" fullword wide
		$op1 = { 78 c4 40 00 ff ff ff ff b4 47 41 }
		$op2 = { 9b 68 b2 34 46 00 eb 14 8d 55 e4 8d 45 e8 52 50 }

	condition:
		uint16(0)==0x5a4d and filesize <=2000KB and 3 of them
}
