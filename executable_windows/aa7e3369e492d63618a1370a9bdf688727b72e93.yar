rule Trojan_Win32_Plakpeer
{
	meta:
		author = "Microsoft"
		description = "Zc tool v2"
		original_sample_sha1 = "2155c20483528377b5e3fde004bb604198463d29"
		unpacked_sample_sha1 = "dc991ef598825daabd9e70bac92c79154363bab2"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "@@E0020(%d)" wide
		$str2 = /exit.{0,3}@exit.{0,3}new.{0,3}query.{0,3}rcz.{0,3}scz/ wide
		$str3 = "---###---" wide
		$str4 = "---@@@---" wide

	condition:
		$str1 and $str2 and $str3 and $str4
}
