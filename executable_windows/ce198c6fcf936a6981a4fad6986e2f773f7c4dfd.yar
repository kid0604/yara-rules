rule _user_task_update_0
{
	meta:
		description = "9893_files - from files user.exe, task_update.exe"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
		date = "2022-03-21"
		hash1 = "7b5fbbd90eab5bee6f3c25aa3c2762104e219f96501ad6a4463e25e6001eb00b"
		hash2 = "12c6da07da24edba13650cd324b2ad04d0a0526bb4e853dee03c094075ff6d1a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "-InitOnceExecuteOnce" fullword ascii
		$s2 = "PB_GadgetStack_%I64i" fullword ascii
		$s3 = "PB_DropAccept" fullword ascii
		$s4 = "PB_PostEventMessage" fullword ascii
		$s5 = "PB_WindowID" fullword ascii
		$s6 = "?GetLongPathNameA" fullword ascii
		$s7 = "Memory page error" fullword ascii
		$s8 = "PPPPPPH" fullword ascii
		$s9 = "YZAXAYH" fullword ascii
		$s10 = "%d:%I64d:%I64d:%I64d" fullword ascii
		$s11 = "PYZAXAYH" fullword ascii
		$s12 = "PB_MDI_Gadget" fullword ascii
		$s13 = "PostEventClass" fullword ascii
		$s14 = "t$hYZAXAYH" fullword ascii
		$s15 = "$YZAXAYH" fullword ascii
		$s16 = "Floating-point underflow (exponent too small)" fullword ascii
		$s17 = "Inexact floating-point result" fullword ascii
		$s18 = "Single step trap" fullword ascii
		$s19 = "Division by zero (floating-point)" fullword ascii
		$s20 = "tmHcI(H" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and (8 of them )) or ( all of them )
}
