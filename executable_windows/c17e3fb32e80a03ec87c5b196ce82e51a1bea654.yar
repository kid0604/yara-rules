import "pe"

rule INDICATOR_KB_CERT_0ced87bd70b092cb93b182fac32655f6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "97b7602ed71480756cf6e4658a107f8278a48096"
		hash = "083d5efb4da09432a206cb7fba5cef2c82dd6cc080015fe69c2b36e71bca6c89"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Creator Soft Limited" and pe.signatures[i].serial=="0c:ed:87:bd:70:b0:92:cb:93:b1:82:fa:c3:26:55:f6")
}
