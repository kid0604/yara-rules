rule Lazarus_packer_code
{
	meta:
		description = "Lazarus using packer"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "b114b1a6aecfe6746b674f1fdd38a45d9a6bb1b4eb0b0ca2fdb270343f7c7332"
		hash2 = "5f3353063153a29c8c3075ffb1424b861444a091d9007e6f3b448ceae5a3f02e"
		os = "windows"
		filetype = "executable"

	strings:
		$code = { 55 8B EC A1 ?? ?? ?? 00 83 C0 01 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 ( 01 | 02 | 03 | 04 | 05 ) 76 16 8B 0D ?? ?? ?? 00 83 E9 01 89 0D ?? ?? ?? 00 B8 ?? ?? ?? ?? EB  }

	condition:
		all of them
}
