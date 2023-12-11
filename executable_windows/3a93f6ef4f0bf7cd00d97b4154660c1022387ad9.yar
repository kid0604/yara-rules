rule Ransom_Cryptolocker_2
{
	meta:
		description = "Detect the risk of Ransomware CryptoLocker Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = {8B454821E8306DCFFF63804528050000}

	condition:
		uint16(0)==0x5a4d and all of them
}
