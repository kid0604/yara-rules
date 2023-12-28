rule Lazarus_downloader_code
{
	meta:
		description = "Lazarus downloader"
		author = "JPCERT/CC Incident Response Group"
		hash = "faba4114ada285987d4f7c771f096e0a2bc4899c9244d182db032acd256c67aa"
		os = "windows"
		filetype = "executable"

	strings:
		$jmp = { 53 31 c0 50 50 50 50 50 C7 ?? ?? 00 00 00 00 EB 00 }
		$count = { 00 00 EB 00 B8 FF 59 62 02 3B 05 ?? ?? ?? 00 }
		$api = "InitOnceExecuteOnce" ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and filesize <200KB and all of them
}
