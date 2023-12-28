rule BlackTech_TSCookie_loader
{
	meta:
		description = "detect tscookie loader"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "PE file search"
		hash1 = "a800df1b8ffb4fbf42bccb4a8af31c7543de3bdba1207e703d6df464ec4398e6"
		hash2 = "b548a7ad37d241b7a7762bb84a3b0125772c469ef5f8e5e0ea190fa2458a018c"
		os = "windows"
		filetype = "executable"

	strings:
		$rc4key = {C7 [1-6] 92 5A 76 5D}
		$rc4loop = {3D 00 01 00 00}

	condition:
		( uint16(0)==0x5A4D) and ( filesize <2MB) and all of ($rc4*)
}
