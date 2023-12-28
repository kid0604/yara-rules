rule darkhotel_dotNetDownloader_strings
{
	meta:
		description = "detect dotNetDownloader"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "PE file search"
		reference = "internal research"
		hash1 = "d95ebbbe664b6ff75cf314b267501a5fa22e896524e6812092ae294e56b4ed44"
		hash2 = "9da9fe6af141a009f28ee37b4edba715e9d77a058b1469b4076b4ea2761e37c4"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb = "C:\\xingxing\\snowball\\Intl_Cmm_Inteface_Buld_vesion2.6\\IMGJPS.pdb" fullword nocase
		$a1 = "4d1d3972223f623f36650c00633f247433244d5c" ascii fullword
		$b1 = "snd1vPng" ascii fullword
		$b2 = "sdMsg" ascii fullword
		$b3 = "rqPstdTa" ascii fullword
		$b4 = "D0w1ad" ascii fullword
		$b5 = "U1dAL1" ascii fullword

	condition:
		( uint16(0)==0x5A4D) and ( filesize <200KB) and (($pdb) or ($a1) or (3 of ($b*)))
}
