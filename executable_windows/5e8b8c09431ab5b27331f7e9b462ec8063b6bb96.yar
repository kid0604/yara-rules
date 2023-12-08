import "pe"
import "hash"

rule dragos_crashoverride_configReader
{
	meta:
		description = "CRASHOVERRIDE v1 Config File Parsing"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = { 68 e8 ?? ?? ?? 6a 00 e8 a3 ?? ?? ?? 8b f8 83 c4 ?8 }
		$s1 = { 8a 10 3a 11 75 ?? 84 d2 74 12 }
		$s2 = { 33 c0 eb ?? 1b c0 83 c8 ?? }
		$s3 = { 85 c0 75 ?? 8d 95 ?? ?? ?? ?? 8b cf ?? ?? }

	condition:
		all of them
}
