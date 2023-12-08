rule Regin_Sample_3
{
	meta:
		description = "Detects Regin Backdoor sample fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
		author = "@Malwrsignatures"
		date = "27.11.14"
		hash = "fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Service Pack x" fullword wide
		$s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide
		$s2 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\HotFix" wide
		$s3 = "mntoskrnl.exe" fullword wide
		$s4 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management" wide
		$s5 = "Memory location: 0x%p, size 0x%08x" wide fullword
		$s6 = "Service Pack" fullword wide
		$s7 = ".sys" fullword wide
		$s8 = ".dll" fullword wide
		$s10 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Updates" wide
		$s11 = "IoGetRelatedDeviceObject" fullword ascii
		$s12 = "VMEM.sys" fullword ascii
		$s13 = "RtlGetVersion" fullword wide
		$s14 = "ntkrnlpa.exe" fullword ascii

	condition:
		uint32(0)==0xfedcbafe and all of ($s*) and filesize >160KB and filesize <200KB
}
