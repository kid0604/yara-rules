import "pe"

rule INDICATOR_KB_CERT_0f0ed5318848703405d40f7c62d0f39a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ed91194ee135b24d5df160965d8036587d6c8c35"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SIES UPRAVLENIE PROTSESSAMI, OOO" and pe.signatures[i].serial=="0f:0e:d5:31:88:48:70:34:05:d4:0f:7c:62:d0:f3:9a")
}
