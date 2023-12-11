import "math"
import "pe"

rule mimi_anti1
{
	meta:
		description = "Detect the risk of Malware Mimikatz Rule 16"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
		$s2 = "gSAMLIB.dll" fullword ascii
		$s3 = "QVERSION.dll" fullword ascii
		$s4 = "mimikatz.exe" fullword wide
		$s5 = "yCRYPT32.dll" fullword ascii
		$s6 = "YSHLWAPI.dll" fullword ascii
		$s7 = "Pmsasn1.dll" fullword ascii
		$s8 = "[cWINSTA.dll" fullword ascii
		$s9 = "curity><requestedPrivileges><requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel" ascii
		$s10 = "7http://sha256timestamp.ws.symantec.com/sha256/timestamp0" fullword ascii
		$s11 = "www.microsoft.com0" fullword ascii
		$s12 = "=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
		$s13 = "mimikatz" fullword wide
		$s14 = "Copyright (c) 2007 - 2019 gentilkiwi (Benjamin DELPY)" fullword wide
		$s15 = "mimikatz for Windows" fullword wide
		$s16 = "U:\"QS6" fullword ascii
		$s17 = "fjN.TRl" fullword ascii
		$s18 = "^f:\"Oh" fullword ascii
		$s19 = "QZ0S.aLe" fullword ascii
		$s20 = "3%i:^3" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <18000KB and 8 of them
}
