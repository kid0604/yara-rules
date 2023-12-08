import "pe"

rule antivm_vmware
{
	meta:
		author = "x0r"
		description = "AntiVM checks for VMWare"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "vmware.exe" nocase
		$s2 = "vmware-authd.exe" nocase
		$s3 = "vmware-hostd.exe" nocase
		$s4 = "vmware-tray.exe" nocase
		$s5 = "vmware-vmx.exe" nocase
		$s6 = "vmnetdhcp.exe" nocase
		$s7 = "vpxclient.exe" nocase
		$s8 = { b868584d56bb00000000b90a000000ba58560000ed }

	condition:
		any of them
}
