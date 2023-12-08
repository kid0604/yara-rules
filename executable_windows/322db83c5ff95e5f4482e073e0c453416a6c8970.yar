import "pe"

rule MALWARE_Win_DLInjector01
{
	meta:
		author = "ditekSHen"
		description = "Detects specific downloader injector shellcode"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "process call create \"%s\"" ascii wide
		$s2 = "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Enum\\" ascii wide
		$s3 = "%systemroot%\\system32\\ntdll.dll" ascii wide
		$s4 = "qemu-ga.exe" ascii wide
		$s5 = "prl_tools.exe" ascii wide
		$s6 = "vboxservice.exe" ascii wide
		$o1 = { 75 04 74 02 38 6e 8b 34 24 83 c4 04 eb 0a 08 81 }
		$o2 = { 16 f8 f7 ba f0 3d 87 c7 95 13 b7 64 22 be e1 59 }
		$o3 = { 8b 0c 24 83 c4 04 eb 05 ea f2 eb ef 05 e8 ad fe }
		$o4 = { eb 05 1d 51 eb f5 ce e8 80 fd ff ff 77 a1 f4 cd }
		$o5 = { eb 05 6e 33 eb f5 73 e8 64 f6 ff ff 77 a1 f4 77 }
		$o6 = { 59 eb 05 fd 98 eb f4 50 e8 d5 f5 ff ff 3b b9 00 }
		$o7 = "bYkoDA7G" fullword ascii

	condition:
		( uint16(0)==0x5a4d and all of ($o*)) or ( all of ($s*))
}
