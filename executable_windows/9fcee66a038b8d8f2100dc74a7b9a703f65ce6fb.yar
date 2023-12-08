import "pe"

rule MALWARE_Win_Quantum
{
	meta:
		author = "ditekSHen"
		description = "Detects Quantum locker / ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\t<title>Quantum</title>" ascii wide
		$x2 = "Quantum Locker.<br><br>" ascii wide
		$s1 = "ERROR" fullword wide
		$s2 = ".log" fullword wide
		$s3 = "SLOW" fullword wide
		$s4 = "Create" fullword wide
		$s5 = "Integrity" fullword wide
		$s6 = "Disabled" fullword wide
		$s7 = "Deny" fullword wide
		$s8 = "FAST" fullword wide
		$s9 = "Mandatory" fullword wide
		$s10 = "plugin.dll" fullword ascii
		$s11 = "NetGetDCName" fullword ascii
		$s12 = "NetShareEnum" fullword ascii
		$s13 = "NetGetJoinInformation" fullword ascii

	condition:
		( uint16(0)==0x5a4d and ( all of ($x*) or 9 of ($s*) or (pe.number_of_exports==2 and pe.exports("RunW") and pe.exports("runW") and 5 of ($s*)))) or all of ($x*)
}
