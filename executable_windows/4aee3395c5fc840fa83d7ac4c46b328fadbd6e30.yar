import "pe"

rule INDICATOR_KB_CERT_309368b122ab63103dddd4ad6321a82c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1370de077e2ba2065478dee8075b16c0e5a5e862"
		hash1 = "b7376049b73feb5bc677a02e4040f2ec7e7302456db9eac35c71072dd95557eb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Systems Accounting Limited" and pe.signatures[i].serial=="30:93:68:b1:22:ab:63:10:3d:dd:d4:ad:63:21:a8:2c")
}
