import "math"
import "pe"

rule mimi_anti2
{
	meta:
		description = "Detect the risk of Malware Mimikatz Rule 17"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "mimikatz.exe" fullword wide
		$s2 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
		$s3 = "7http://sha256timestamp.ws.symantec.com/sha256/timestamp0" fullword ascii
		$s4 = "www.microsoft.com0" fullword ascii
		$s5 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
		$s6 = "mimikatz" fullword wide
		$s7 = "Copyright (c) 2007 - 2019 gentilkiwi (Benjamin DELPY)" fullword wide
		$s8 = "msncucx" fullword ascii
		$s9 = "ashcjsm" fullword ascii
		$s10 = "lsmcpst" fullword ascii
		$s11 = "iRNG9+ >" fullword ascii
		$s12 = "mzhn9+ " fullword ascii
		$s13 = "mimikatz for Windows" fullword wide
		$s14 = "yDT:\\pE" fullword ascii
		$s15 = "RiRC<m" fullword ascii
		$s16 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
		$s17 = "GEt:h5Wm" fullword ascii
		$s18 = "Zlaocpz" fullword ascii
		$s19 = "Qnsfqlc" fullword ascii
		$s20 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii

	condition:
		uint16(0)==0x5a4d and filesize <18000KB and 8 of them
}
