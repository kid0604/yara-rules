rule INDICATOR_TOOL_CNC_Shootback
{
	meta:
		author = "ditekSHen"
		description = "detects Python executable for CnC communication via reverse tunnels. Used by MuddyWater group."
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PYTHON27.DLL" fullword wide
		$s2 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyR" fullword ascii
		$s3 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyt" fullword ascii
		$s4 = "subprocess.pyc" fullword ascii
		$s5 = "MyGetProcAddress(%p, %p(%s)) -> %p" fullword ascii
		$p1 = "Slaver(this pc):" ascii
		$p2 = "Master(another public server):" ascii
		$p3 = "Master(this pc):" ascii
		$p4 = "running as slaver, master addr: {} target: {}R/" fullword ascii
		$p5 = "Customer(this pc): " ascii
		$p6 = "Customer(any internet user):" ascii
		$p7 = "the actual traffic is:  customer <--> master(1.2.3.4) <--> slaver(this pc) <--> ssh(this pc)" fullword ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($s*) and 2 of ($p*))
}
