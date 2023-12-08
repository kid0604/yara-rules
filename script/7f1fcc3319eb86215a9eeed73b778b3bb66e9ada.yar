rule Msfpayloads_msf_4
{
	meta:
		description = "Metasploit Payloads - file msf.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "26b3e572ba1574164b76c6d5213ab02e4170168ae2bcd2f477f246d37dbe84ef"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "= VirtualAlloc(IntPtr.Zero,(UIntPtr)" ascii
		$s2 = ".Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);" ascii
		$s3 = "[System.Runtime.InteropServices.DllImport(\"kernel32\")]" fullword ascii
		$s4 = "private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;" fullword ascii
		$s5 = "private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);" fullword ascii

	condition:
		4 of them
}
