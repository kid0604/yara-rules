rule Lazarus_loader_thumbsdb
{
	meta:
		description = "Loader Thumbs.db malware in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "44e4e14f8c8d299ccf5194719ab34a21ad6cc7847e49c0a7de05bf2371046f02"
		os = "windows"
		filetype = "executable"

	strings:
		$switchcase = { E8 ?? ?? ?? ?? 83 F8 64 74 ?? 3D C8 00 00 00 74 ?? 3D 2C 01 00 00 75 ?? E8 ?? ?? ?? ?? B9 D0 07 00 00 E8 }

	condition:
		all of them
}
