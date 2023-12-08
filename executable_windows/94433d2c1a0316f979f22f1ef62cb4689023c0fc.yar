import "math"
import "pe"

rule mimi_anti
{
	meta:
		description = "Detect the risk of Malware Mimikatz Rule 15"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
		$s2 = "mZXixFpg.exe" fullword wide
		$s3 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
		$s4 = "Copyright (c) 2007 - 2020 bIJ9xgPw5o (eTZHxXXY 52DdH)" fullword wide
		$s5 = "GcircTRv" fullword ascii
		$s6 = "acossqrt" fullword ascii
		$s7 = "baagqqq" fullword ascii
		$s8 = "nnmdjjj" fullword ascii
		$s9 = "jklmnop" fullword ascii
		$s10 = "onoffalsey" fullword ascii
		$s11 = "NCKeyD`<d" fullword ascii
		$s12 = "lCorE.Proces" fullword ascii
		$s13 = "RRR.uuu" fullword ascii
		$s14 = " erroFail" fullword ascii
		$s15 = "Q.0F:\\" fullword ascii
		$s16 = ".c:%d:%" fullword ascii
		$s17 = "CHPJHAT" fullword ascii
		$s18 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
		$s19 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii
		$s20 = " @-OPrAT" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 8 of them
}
