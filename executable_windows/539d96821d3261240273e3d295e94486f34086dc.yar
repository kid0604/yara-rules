import "pe"
import "hash"

rule dragos_crashoverride_serviceStomper
{
	meta:
		description = "Identify service hollowing and persistence setting"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = { 33 c9 51 51 51 51 51 51 ?? ?? ?? }
		$s1 = { 6a ff 6a ff 6a ff 50 ff 15 24 ?? 40 00 ff ?? ?? ff 15 20 ?? 40 00 }

	condition:
		all of them
}
