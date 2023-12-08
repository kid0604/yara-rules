import "pe"

rule INDICATOR_KB_CERT_279b3a26f16a069aa7bca1811d44ad9b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4a9fc15f1d63145b622989c4f5bec4612095401e"
		hash1 = "fc642048d9f0b8cb36649fd377fdb68dce3998f2a88e8c64acdc4e88435f2562"
		hash2 = "914067034336e4ed8b56e66d6be29f34477d9fb38ba73095a3edca5ec9cb1a9c"
		hash3 = "daf7e148f82807808cac8a21b1a3ce43491c3a140420442a1c1ee2d497a9e0a2"
		hash4 = "3727044bebe4a14aed66df5119c11471a57b50c57ab4baaef4073323206d3b9b"
		hash5 = "f0239d16f77b11e6b606b23a53c9e563f6360a27a03c0b9cf83b151ee8ee9088"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DIGITAL DEVLIN LIMITED" and pe.signatures[i].serial=="27:9b:3a:26:f1:6a:06:9a:a7:bc:a1:81:1d:44:ad:9b")
}
