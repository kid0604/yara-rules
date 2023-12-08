import "pe"

rule MALWARE_Win_iTranslatorDLL
{
	meta:
		author = "ditekSHen"
		description = "Detects iTranslator DLL payload"
		clamav_sig = "MALWARE.Win.Trojan.iTranslator_DLL"
		os = "windows"
		filetype = "executable"

	strings:
		$d1 = "system32\\drivers\\%S.sys" fullword wide
		$d2 = "\\windows\\system32\\winlogon.exe" fullword ascii
		$d3 = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\%s" fullword wide
		$d4 = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\webssx" fullword wide
		$d5 = "\\Device\\CtrlSM" fullword wide
		$d6 = "\\DosDevices\\CtrlSM" fullword wide
		$d7 = "\\driver_wfp\\CbFlt\\Bin\\CbFlt.pdb" ascii
		$d8 = ".php" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
