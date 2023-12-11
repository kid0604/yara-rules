import "pe"

rule INDICATOR_KB_CERT_008385684419ab26a3f2640b1496e1fe94
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ee1d7d90957f3f2ccfcc069f5615a5bafdac322f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CAUSE FOR CHANGE LTD" and pe.signatures[i].serial=="00:83:85:68:44:19:ab:26:a3:f2:64:0b:14:96:e1:fe:94")
}
