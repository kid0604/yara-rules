rule MAL_ELF_LNX_Mirai_Oct10_2
{
	meta:
		description = "Detects ELF malware Mirai related"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-10-27"
		hash1 = "fa0018e75f503f9748a5de0d14d4358db234f65e28c31c8d5878cc58807081c9"
		os = "linux"
		filetype = "executable"

	strings:
		$c01 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F 00 00
               20 48 54 54 50 2F 31 2E 31 0D 0A 55 73 65 72 2D
               41 67 65 6E 74 3A 20 00 0D 0A 48 6F 73 74 3A }

	condition:
		uint16(0)==0x457f and filesize <200KB and all of them
}
