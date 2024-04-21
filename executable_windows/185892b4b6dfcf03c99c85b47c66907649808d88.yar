rule task_update
{
	meta:
		description = "9893_files - file task_update.exe"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
		date = "2022-03-21"
		hash1 = "12c6da07da24edba13650cd324b2ad04d0a0526bb4e853dee03c094075ff6d1a"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
		$s2 = " or \"requireAdministrator\" --> <v3:requestedExecutionLevel level=\"requireAdministrator\" /> </v3:requestedPrivileges> </v3:se" ascii
		$s3 = "-InitOnceExecuteOnce" fullword ascii
		$s4 = "> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0" ascii
		$s5 = "v3=\"urn:schemas-microsoft-com:asm.v3\"> <v3:security> <v3:requestedPrivileges> <!-- level can be \"asInvoker\", \"highestAvaila" ascii
		$s6 = "PB_GadgetStack_%I64i" fullword ascii
		$s7 = "PB_DropAccept" fullword ascii
		$s8 = "PB_PostEventMessage" fullword ascii
		$s9 = "PB_WindowID" fullword ascii
		$s10 = "?GetLongPathNameA" fullword ascii
		$s11 = "cessorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly> </dependency> <v3:trustInfo " ascii
		$s12 = "Memory page error" fullword ascii
		$s13 = "PPPPPPH" fullword ascii
		$s14 = "YZAXAYH" fullword ascii
		$s15 = "%d:%I64d:%I64d:%I64d" fullword ascii
		$s16 = "PYZAXAYH" fullword ascii
		$s17 = "PB_MDI_Gadget" fullword ascii
		$s18 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
		$s19 = " 11FCC18FB2B55FC3C988F6A76FCF8A2D 56D49E57AD1A051BF62C458CD6F3DEA9 6104990DFEA3DFAB044FAF960458DB09" fullword wide
		$s20 = "PostEventClass" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 1 of ($x*) and 4 of them
}
