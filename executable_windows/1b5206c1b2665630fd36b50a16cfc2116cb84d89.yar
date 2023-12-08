rule APT_MAL_NK_Lazarus_VHD_Ransomware_Oct20_1
{
	meta:
		description = "Detects Lazarus VHD Ransomware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
		date = "2020-10-05"
		hash1 = "52888b5f881f4941ae7a8f4d84de27fc502413861f96ee58ee560c09c11880d6"
		hash2 = "5e78475d10418c6938723f6cfefb89d5e9de61e45ecf374bb435c1c99dd4a473"
		hash3 = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "HowToDecrypt.txt" wide fullword
		$s2 = "rsa.cpp" wide fullword
		$s3 = "sc stop \"Microsoft Exchange Compliance Service\"" ascii fullword
		$op1 = { 8b 8d bc fc ff ff 8b 94 bd 34 03 00 00 33 c0 50 }
		$op2 = { 8b 8d 98 f9 ff ff 8d 64 24 00 8b 39 3b bc 85 34 }
		$op3 = { 8b 94 85 34 03 00 00 89 11 40 83 c1 04 3b 06 7c }

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 2 of them
}
