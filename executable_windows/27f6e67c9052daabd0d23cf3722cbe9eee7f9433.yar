import "pe"

rule SUSP_MAL_SigningCert_Feb24_1
{
	meta:
		description = "Detects PE files signed with a certificate used to sign malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		date = "2024-02-23"
		score = 75
		hash1 = "37a39fc1feb4b14354c4d4b279ba77ba51e0d413f88e6ab991aad5dd6a9c231b"
		hash2 = "e8c48250cf7293c95d9af1fb830bb8a5aaf9cfb192d8697d2da729867935c793"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Wisdom Promise Security Technology Co." ascii
		$s2 = "Globalsign TSA for CodeSign1" ascii
		$s3 = { 5D AC 0B 6C 02 5A 4B 21 89 4B A3 C2 }

	condition:
		uint16(0)==0x5a4d and filesize <70000KB and all of them
}
