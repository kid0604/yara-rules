import "pe"

rule INDICATOR_KB_CERT_010000000001302693cb45
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "bc5fcb5a2b5e0609e2609cff5e272330f79b2375"
		hash = "74069d20e8b8299590420c9af2fdc8856c14d94929c285948585fc89ab2f938f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AutoIt Consulting Ltd" and pe.signatures[i].serial=="01:00:00:00:00:01:30:26:93:cb:45")
}
