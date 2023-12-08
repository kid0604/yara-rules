import "hash"
import "pe"

rule dragos_crashoverride_exporting_dlls
{
	meta:
		description = "CRASHOVERRIDE v1 Suspicious Export"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
		os = "windows"
		filetype = "executable"

	condition:
		pe.exports("Crash")&pe.characteristics
}
