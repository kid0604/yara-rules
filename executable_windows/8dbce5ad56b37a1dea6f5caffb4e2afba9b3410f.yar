import "pe"

rule INDICATOR_KB_CERT_02c5351936abe405ac760228a40387e8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "1174c2affb0a364c1b7a231168cfdda5989c04c5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RESURS-RM OOO" and pe.signatures[i].serial=="02:c5:35:19:36:ab:e4:05:ac:76:02:28:a4:03:87:e8")
}
