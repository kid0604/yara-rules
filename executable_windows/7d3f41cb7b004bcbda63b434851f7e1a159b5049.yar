rule Regin_Sample_Set_1
{
	meta:
		description = "Detects Regin Backdoor sample"
		author = "@MalwrSignatures"
		date = "27.11.14"
		modified = "2023-01-06"
		hash1 = "4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be"
		hash2 = "e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
		os = "windows"
		filetype = "executable"

	strings:
		$hd = { fe ba dc fe }
		$s0 = "d%ls%ls" fullword wide
		$s1 = "\\\\?\\UNC" fullword wide
		$s2 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword wide
		$s4 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
		$s5 = "System\\CurrentControlSet\\Services\\Tcpip\\Linkage" wide fullword
		$s6 = "\\\\.\\Global\\%s" fullword wide
		$s7 = "temp" fullword wide
		$s8 = "\\\\.\\%s" fullword wide
		$s9 = "Memory location: 0x%p, size 0x%08x" fullword wide
		$s10 = "sscanf" fullword ascii
		$s11 = "disp.dll" fullword ascii
		$s12 = "%x:%x:%x:%x:%x:%x:%x:%x%c" fullword ascii
		$s13 = "%d.%d.%d.%d%c" fullword ascii
		$s14 = "imagehlp.dll" fullword ascii
		$s15 = "%hd %d" fullword ascii

	condition:
		($hd at 0) and all of ($s*) and filesize <450KB and filesize >360KB
}
