import "pe"

rule INDICATOR_KB_CERT_4697c7ddd3e37fe275fdc6961a9093e3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ef24ae3635929c371d1427901082be9f76e58d9a"
		hash1 = "fb3f622cf5557364a0a3abacc3e9acf399b3631bf3630acb8132514c486751e7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xC3\\x89tienne Hill" and pe.signatures[i].serial=="46:97:c7:dd:d3:e3:7f:e2:75:fd:c6:96:1a:90:93:e3")
}
