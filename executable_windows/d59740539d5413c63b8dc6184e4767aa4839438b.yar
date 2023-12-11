import "pe"

rule SUSP_Fake_AMSI_DLL_Jun23_1
{
	meta:
		description = "Detects an amsi.dll that has the same exports as the legitimate one but very different contents or file sizes"
		author = "Florian Roth"
		reference = "https://twitter.com/eversinc33/status/1666121784192581633?s=20"
		date = "2023-06-07"
		modified = "2023-06-12"
		score = 65
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Microsoft.Antimalware.Scan.Interface" ascii
		$a2 = "Amsi.pdb" ascii fullword
		$a3 = "api-ms-win-core-sysinfo-" ascii
		$a4 = "Software\\Microsoft\\AMSI\\Providers" wide
		$a5 = "AmsiAntimalware@" ascii
		$a6 = "AMSI UAC Scan" ascii
		$fp1 = "Wine builtin DLL"

	condition:
		uint16(0)==0x5a4d and (pe.exports("AmsiInitialize") and pe.exports("AmsiScanString")) and ( filesize >200KB or filesize <35KB or not 4 of ($a*)) and not 1 of ($fp*)
}
