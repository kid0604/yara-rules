import "pe"

rule Win_MSIL_Ransom
{
	meta:
		description = "Detect the risk of Ransomware Common Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "RijndaelManaged" ascii
		$a2 = "GetDirectories" ascii
		$a3 = "password" ascii
		$a4 = "System.IO" ascii
		$a5 = "GetFiles" ascii
		$a6 = "System.Security.Cryptography" fullword ascii
		$a7 = "encryptDirectory" fullword ascii
		$b4 = "files have been encrypted" ascii wide nocase
		$b5 = "files has been encrypted" ascii wide nocase
		$b6 = "EncryptFile" ascii
		$c1 = ".doc" fullword ascii wide
		$c2 = ".docx" fullword ascii wide
		$c3 = ".xls" fullword ascii wide
		$c4 = ".xlsx" fullword ascii wide
		$c5 = ".ppt" fullword ascii wide
		$c6 = ".pptx" fullword ascii wide
		$c7 = ".html" fullword ascii wide
		$d1 = "Windows" fullword ascii wide
		$d2 = "Program Files (x86)" fullword ascii wide
		$d3 = "GetExtension" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and ( all of ($a*) or (2 of ($b*) and 5 of ($a*)) or ( all of ($c*) and 5 of ($a*)) or ( all of ($d*) and 6 of ($a*))) and pe.imphash()=="f34d5f2d4577ed6d9ceec516c1f5a744"
}
