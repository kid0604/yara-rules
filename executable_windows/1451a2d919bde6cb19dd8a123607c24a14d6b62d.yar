import "pe"

rule INDICATOR_KB_CERT_73b60719ee57974447c68187e49969a2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "8e50ddad9fee70441d9eb225b3032de4358718dc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BIT HORIZON LIMITED" and pe.signatures[i].serial=="73:b6:07:19:ee:57:97:44:47:c6:81:87:e4:99:69:a2")
}
