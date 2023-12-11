import "pe"

rule apt_regin_2011_32bit_stage1
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Regin 32 bit stage 1 loaders"
		version = "1.0"
		last_modified = "2014-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$key1 = {331015EA261D38A7}
		$key2 = {9145A98BA37617DE}
		$key3 = {EF745F23AA67243D}
		$mz = "MZ"

	condition:
		($mz at 0) and any of ($key*) and filesize <300000
}
