rule Ransom_CryptoLocker
{
	meta:
		description = "Detect the risk of Ransomware CryptoLocker Rule 1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = {558BEC83EC0C56C745F8240100008B45}
		$s2 = {8B45F82DE92E00002B45F48945F48D05}

	condition:
		uint16(0)==0x5a4d and all of them
}
