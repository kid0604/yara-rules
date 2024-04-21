rule case_19438_files_MalFiles_PCICL32
{
	meta:
		description = "19438 - file PCICL32.DLL"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "38684adb2183bf320eb308a96cdbde8d1d56740166c3e2596161f42a40fa32d5"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "AttemptLogon - Secur32.dll NOT found!!!" fullword ascii
		$x2 = "You do not have sufficient rights at Client %s to perform this operation. Log in as a different user or contact the Administrato" wide
		$x3 = "NWarning: attempt to login as user %s failed when reading configuration file %s(Error Loading Bridge: Command line error$Error l" wide
		$x4 = "LogonUserWithCert - Crypt32.dll NOT found!!!" fullword ascii
		$x5 = "AttemptLogon - Secur32.dll does not provide required functionality" fullword ascii
		$x6 = "cmd.exe /C start %s" fullword ascii
		$x7 = "Check9xLogon -  [bLoggedIn: %u] send command %d to connections" fullword ascii
		$x8 = "LogonUserWithCert - Advapi32.dll does NOT provide required functionality!" fullword ascii
		$x9 = "LogonUserWithCert - Crypt32.dll does NOT provide required functionality!" fullword ascii
		$s10 = "nsmexec.exe" fullword ascii
		$s11 = "Error. ExecProcessAsUser ret %d" fullword ascii
		$s12 = "c:\\program files\\common files\\microsoft shared\\ink\\tabtip.exe" fullword ascii
		$s13 = "sas.dll" fullword ascii
		$s14 = "DoNSMProtect - PASSWORDS DO NOT MATCH!!!" fullword ascii
		$s15 = "CreateMutex() FAILED - mutex: %s (%d)" fullword ascii
		$s16 = "WaitForSingleObject() FAILED - mutex: %s res: 0x%x (%d)" fullword ascii
		$s17 = "ReleaseMutex() FAILED - mutex: %s (%d)" fullword ascii
		$s18 = "\"cscript.exe\" %s -d  -p \"%s\"" fullword ascii
		$s19 = "\"cscript.exe\" %s -d -r %s" fullword ascii
		$s20 = "\"cscript.exe\" %s -a -p \"%s\" -m \"%s\" -r \"%s\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <11000KB and 1 of ($x*) and all of them
}
