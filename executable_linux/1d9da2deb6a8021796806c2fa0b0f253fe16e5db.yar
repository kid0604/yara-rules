rule apt_RU_MoonlightMaze_IRIX_exploit_GEN
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-27"
		version = "1.0"
		last_modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect Irix exploits from David Hedley used by Moonlight Maze hackers"
		reference2 = "https://www.exploit-db.com/exploits/19274/"
		hash = "008ea82f31f585622353bd47fa1d84be"
		hash = "a26bad2b79075f454c83203fa00ed50c"
		hash = "f67fc6e90f05ba13f207c7fdaa8c2cab"
		hash = "5937db3896cdd8b0beb3df44e509e136"
		hash = "f4ed5170dcea7e5ba62537d84392b280"
		os = "linux"
		filetype = "executable"

	strings:
		$a1 = "stack = 0x%x, targ_addr = 0x%x"
		$a2 = "execl failed"

	condition:
		( uint32(0)==0x464c457f) and ( all of them )
}
