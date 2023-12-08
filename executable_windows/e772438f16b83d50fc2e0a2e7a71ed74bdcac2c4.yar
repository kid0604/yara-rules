import "pe"

rule INDICATOR_KB_CERT_00e5d20477e850c9f35c5c47123ef34271
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "d11431836db24dcc3a17de8027ab284a035f2e4f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xD0\\x92\\xE5\\xBE\\xB7\\xE8\\x89\\xBE\\xE5\\x8B\\x92\\xD0\\x92\\xE8\\xB4\\x9D\\xE8\\x89\\xBE\\xE5\\xBE\\xB7\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92\\xE8\\xB4\\x9D\\xE5\\x8B\\x92\\xD0\\x92\\xE5\\xBE\\xB7\\xE8\\xB4\\x9D\\xD0\\x92\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92" and pe.signatures[i].serial=="00:e5:d2:04:77:e8:50:c9:f3:5c:5c:47:12:3e:f3:42:71")
}
