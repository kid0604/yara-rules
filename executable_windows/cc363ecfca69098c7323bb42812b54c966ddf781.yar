import "hash"
import "pe"

rule dragos_crashoverride_name_search
{
	meta:
		description = "CRASHOVERRIDE v1 Suspicious Strings and Export"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "101.dll" fullword nocase wide
		$s1 = "Crash101.dll" fullword nocase wide
		$s2 = "104.dll" fullword nocase wide
		$s3 = "Crash104.dll" fullword nocase wide
		$s4 = "61850.dll" fullword nocase wide
		$s5 = "Crash61850.dll" fullword nocase wide
		$s6 = "OPCClientDemo.dll" fullword nocase wide
		$s7 = "OPC" fullword nocase wide
		$s8 = "CrashOPCClientDemo.dll" fullword nocase wide
		$s9 = "D2MultiCommService.exe" fullword nocase wide
		$s10 = "CrashD2MultiCommService.exe" fullword nocase wide
		$s11 = "61850.exe" fullword nocase wide
		$s12 = "OPC.exe" fullword nocase wide
		$s13 = "haslo.exe" fullword nocase wide
		$s14 = "haslo.dat" fullword nocase wide

	condition:
		any of ($s*) and pe.exports("Crash")
}
