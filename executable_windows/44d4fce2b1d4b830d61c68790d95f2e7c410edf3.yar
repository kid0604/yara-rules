import "pe"

rule apt_regin_legspin_alt_1
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Regin's Legspin module"
		version = "1.0"
		last_modified = "2015-01-22"
		reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
		md5 = "29105f46e4d33f66fee346cfd099d1cc"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$a1 = "sharepw"
		$a2 = "reglist"
		$a3 = "logdump"
		$a4 = "Name:" wide
		$a5 = "Phys Avail:"
		$a6 = "cmd.exe" wide
		$a7 = "ping.exe" wide
		$a8 = "millisecs"

	condition:
		($mz at 0) and all of ($a*)
}
