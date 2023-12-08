rule Trojan_Win32_Plakpers_alt_1 : Platinum
{
	meta:
		author = "Microsoft"
		description = "Injector / loader component"
		original_sample_sha1 = "fa083d744d278c6f4865f095cfd2feabee558056"
		unpacked_sample_sha1 = "3a678b5c9c46b5b87bfcb18306ed50fadfc6372e"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "MyFileMappingObject"
		$str2 = "[%.3u]  %s  %s  %s [%s:" wide
		$str3 = "%s\\{%s}\\%s" wide

	condition:
		$str1 and $str2 and $str3
}
