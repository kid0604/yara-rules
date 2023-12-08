import "pe"

rule INDICATOR_KB_CERT_45eb9187a2505d8e6c842e6d366ad0c8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "63938d34572837514929fa7ae3cfebedf6d2cb65"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BAKERA s.r.o." and pe.signatures[i].serial=="45:eb:91:87:a2:50:5d:8e:6c:84:2e:6d:36:6a:d0:c8")
}
