import "pe"

rule INDICATOR_KB_CERT_009faf8705a3eaef9340800cc4fd38597c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "40c572cc19e7ca4c2fb89c96357eff4c7489958e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tekhnokod LLC" and pe.signatures[i].serial=="00:9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c")
}
