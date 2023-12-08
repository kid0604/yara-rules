import "pe"

rule NetpassStrings : NetPass Variant
{
	meta:
		description = "Identifiers for netpass variant"
		author = "Katie Kleemola"
		last_updated = "2014-05-29"
		os = "windows"
		filetype = "executable"

	strings:
		$exif1 = "Device Protect ApplicatioN" wide
		$exif2 = "beep.sys" wide
		$exif3 = "BEEP Driver" wide
		$string1 = "\x00NetPass Update\x00"
		$string2 = "\x00%s:DOWNLOAD\x00"
		$string3 = "\x00%s:UPDATE\x00"
		$string4 = "\x00%s:uNINSTALL\x00"

	condition:
		all of ($exif*) or any of ($string*)
}
