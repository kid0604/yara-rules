import "pe"

rule MAL_CS_Loader_Feb24_1
{
	meta:
		description = "Detects Cobalt Strike malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		date = "2024-02-23"
		score = 75
		hash1 = "0a492d89ea2c05b1724a58dd05b7c4751e1ffdd2eab3a2f6a7ebe65bf3fdd6fe"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Dll_x86.dll" ascii fullword

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (pe.exports("UpdateSystem") and (pe.imphash()=="0dc05c4c21a86d29f1c3bf9cc5b712e0" or $s1))
}
