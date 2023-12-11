import "pe"
import "hash"

rule dragos_crashoverride_weirdMutex
{
	meta:
		description = "Blank mutex creation assoicated with CRASHOVERRIDE"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 81 ec 08 02 00 00 57 33 ff 57 57 57 ff 15 ?? ?? 40 00 a3 ?? ?? ?? 00 85 c0 }
		$s2 = { 8d 85 ?? ?? ?? ff 50 57 57 6a 2e 57 ff 15 ?? ?? ?? 00 68 ?? ?? 40 00}

	condition:
		all of them
}
