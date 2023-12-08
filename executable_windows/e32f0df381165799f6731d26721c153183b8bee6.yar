rule maindll_mutex
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Matches on the maindll mutex"
		os = "windows"
		filetype = "executable"

	strings:
		$mutex = "h31415927tttt"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and $mutex
}
