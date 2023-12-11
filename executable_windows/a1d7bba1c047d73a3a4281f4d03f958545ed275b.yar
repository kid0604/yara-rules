import "pe"

rule INDICATOR_KB_CERT_0097df46acb26b7c81a13cc467b47688c8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "54c4929195fafddfd333871471a015fa68092f44e2f262f2bbf4ee980b41b809"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Information Civilized System Oy" and pe.signatures[i].serial=="00:97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8")
}
