import "pe"

rule MALWARE_Win_iTranslatorEXE
{
	meta:
		author = "ditekSHen"
		description = "Detects iTranslator EXE payload"
		clamav_sig = "MALWARE.Win.Trojan.iTranslator_EXE"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\itranslator\\wintrans.exe" fullword wide
		$s2 = "\\SuperX\\SuperX\\Obj\\Release\\SharpX.pdb" fullword ascii
		$s3 = "\\itranslator\\itranslator.dll" fullword ascii
		$s4 = ":Intoskrnl.exe" fullword ascii
		$s5 = "InjectDrv.sys" fullword ascii
		$s6 = "SharpX.dll" fullword wide
		$s7 = "GetMicrosoftEdgeProcessId" ascii
		$s8 = ".php?type=is&ch=" ascii
		$s9 = ".php?uid=" ascii
		$s10 = "&mc=" fullword ascii
		$s11 = "&os=" fullword ascii
		$s12 = "&x=32" fullword ascii

	condition:
		uint16(0)==0x5a4d and 8 of ($s*)
}
