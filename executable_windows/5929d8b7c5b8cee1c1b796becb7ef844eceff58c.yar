rule files_user
{
	meta:
		description = "9893_files - file user.exe"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
		date = "2022-03-21"
		hash1 = "7b5fbbd90eab5bee6f3c25aa3c2762104e219f96501ad6a4463e25e6001eb00b"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "PA<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVer" ascii
		$s2 = "\", or \"requireAdministrator\" --> <v3:requestedExecutionLevel level=\"requireAdministrator\" /> </v3:requestedPrivileges> </v3" ascii
		$s3 = "-InitOnceExecuteOnce" fullword ascii
		$s4 = "0\"> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0." ascii
		$s5 = "s:v3=\"urn:schemas-microsoft-com:asm.v3\"> <v3:security> <v3:requestedPrivileges> <!-- level can be \"asInvoker\", \"highestAvai" ascii
		$s6 = "PB_GadgetStack_%I64i" fullword ascii
		$s7 = "PB_DropAccept" fullword ascii
		$s8 = "rocessorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly> </dependency> <v3:trustInf" ascii
		$s9 = "PB_PostEventMessage" fullword ascii
		$s10 = "PB_WindowID" fullword ascii
		$s11 = "?GetLongPathNameA" fullword ascii
		$s12 = "Memory page error" fullword ascii
		$s13 = "PPPPPPH" fullword ascii
		$s14 = "YZAXAYH" fullword ascii
		$s15 = "%d:%I64d:%I64d:%I64d" fullword ascii
		$s16 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
		$s17 = "PYZAXAYH" fullword ascii
		$s18 = "PB_MDI_Gadget" fullword ascii
		$s19 = "PA<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVer" ascii
		$s20 = " 46B722FD25E69870FA7711924BC5304D 787242D55F2C49A23F5D97710D972108 A2DB26CE3BBE7B2CB12F9BEFB37891A3" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 1 of ($x*) and 4 of them
}
