import "pe"

rule SharedStrings : Family
{
	meta:
		description = "Internal names found in LURK0/CCTV0 samples"
		author = "Katie Kleemola"
		last_updated = "07-22-2014"
		os = "windows"
		filetype = "executable"

	strings:
		$i1 = "Butterfly.dll"
		$i2 = /\\BT[0-9.]+\\ButterFlyDLL\\/
		$i3 = "ETClientDLL"
		$d1 = "\\DbxUpdateET\\" wide
		$d2 = "\\DbxUpdateBT\\" wide
		$d3 = "\\DbxUpdate\\" wide
		$mc1 = "\\Micet\\"
		$n1 = "IconCacheEt.dat" wide
		$n2 = "IconConfigEt.dat" wide
		$m1 = "\x00\x00ERXXXXXXX\x00\x00" wide
		$m2 = "\x00\x00111\x00\x00" wide
		$m3 = "\x00\x00ETUN\x00\x00" wide
		$m4 = "\x00\x00ER\x00\x00" wide

	condition:
		any of them
}
