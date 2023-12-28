rule Lazarus_boardiddownloader_code
{
	meta:
		description = "boardid downloader in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash = "fe80e890689b0911d2cd1c29196c1dad92183c40949fe6f8c39deec8e745de7f"
		os = "windows"
		filetype = "executable"

	strings:
		$enchttp = { C7 ?? ?? 06 1A 1A 1E C7 ?? ?? 1D 54 41 41 }
		$xorcode = { 80 74 ?? ?? 6E 80 74 ?? ?? 6E (48 83|83) ?? 02 (48|83) }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and all of them
}
