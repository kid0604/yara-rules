import "pe"

rule powershell_dll
{
	meta:
		description = "11462 - powershell.dll"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com"
		date = "2022-03-22"
		hash1 = "2fcd6a4fd1215facea1fe1a503953e79b7a1cedc4d4320e6ab12461eb45dde30"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "powershell.dll" fullword wide
		$s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
		$s3 = "DynamicDllLoader" fullword ascii
		$s4 = "GetModuleCount" fullword ascii
		$s5 = "fnDllEntry" fullword ascii
		$s6 = "oldHeaders" fullword ascii
		$s7 = "dosHeader" fullword ascii
		$s8 = "IMAGE_EXPORT_DIRECTORY" fullword ascii
		$s9 = "Win32Imports" fullword ascii
		$s10 = "IMAGE_IMPORT_BY_NAME" fullword ascii
		$s11 = "BuildImportTable" fullword ascii
		$s12 = "MEMORYMODULE" fullword ascii
		$s13 = "lpAddress" fullword ascii
		$s14 = "CurrentUser" fullword ascii
		$s15 = "Signature" fullword ascii
		$s16 = "Install" fullword wide
		$s17 = "module" fullword ascii
		$s18 = "Console" fullword ascii
		$s19 = "EndInvoke" fullword ascii
		$s20 = "BeginInvoke" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and 10 of them
}
