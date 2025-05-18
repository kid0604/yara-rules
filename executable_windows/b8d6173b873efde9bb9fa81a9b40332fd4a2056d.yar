import "pe"

rule sig_27138_files_check
{
	meta:
		description = "27138 - file check.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
		date = "2025-01-23"
		hash1 = "3f97e112f0c5ddf0255ef461746a223208dc0846bde2a6dca9c825d9c706a4e9"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\Users\\ad\\source\\repos\\ReadByte\\ReadByte\\obj\\Release\\DiskCheck.pdb" fullword ascii
		$s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
		$s3 = "DiskCheck.exe" fullword wide
		$s4 = "computers.txt" fullword wide
		$s5 = "Error.txt" fullword wide
		$s6 = "SELECT * FROM Win32_LoggedOnUser" fullword wide
		$s7 = "Complete!!!" fullword wide
		$s8 = "LivePc.txt" fullword wide
		$s9 = "DeadPc.txt" fullword wide
		$s10 = "Success!!!" fullword wide
		$s11 = "vSphere!!!" fullword wide
		$s12 = "Synology" fullword wide
		$s13 = "Programs.csv" fullword wide
		$s14 = ".NETFramework,Version=v4.6.2" fullword ascii
		$s15 = ".NET Framework 4.6.2" fullword ascii
		$s16 = "ReadByte.Form1+<Disk>d__5" fullword ascii
		$s17 = "ReadRemoteRegistryusingWMI" fullword ascii
		$s18 = "diskSpace.csv" fullword wide
		$s19 = "ReadByte.Form1.resources" fullword ascii
		$s20 = "SELECT * FROM Win32_MappedLogicalDisk" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <60KB and 1 of ($x*) and 4 of them
}
