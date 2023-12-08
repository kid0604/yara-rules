import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_AntiVM_UNK01
{
	meta:
		author = "ditekSHen"
		description = "Detects memory artifcats referencing specific combination of anti-VM checks"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "vmci.s" fullword ascii wide
		$s2 = "vmmemc" fullword ascii wide
		$s3 = "qemu-ga.exe" fullword ascii wide
		$s4 = "qga.exe" fullword ascii wide
		$s5 = "windanr.exe" fullword ascii wide
		$s6 = "vboxservice.exe" fullword ascii wide
		$s7 = "vboxtray.exe" fullword ascii wide
		$s8 = "vmtoolsd.exe" fullword ascii wide
		$s9 = "prl_tools.exe" fullword ascii wide
		$s10 = "7869.vmt" fullword ascii wide
		$s11 = "qemu" fullword ascii wide
		$s12 = "virtio" fullword ascii wide
		$s13 = "vmware" fullword ascii wide
		$s14 = "vbox" fullword ascii wide
		$s15 = "%systemroot%\\system32\\ntdll.dll" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
