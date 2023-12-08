import "pe"

rule MALWARE_Win_RDPCredsStealerInjector
{
	meta:
		author = "ditekSHen"
		description = "Detects RDP Credentials Stealer injector"
		clamav1 = "MALWARE.Win.Trojan.RDPCredsStealer-Injector"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\APIHookInjectorBin\\" ascii
		$s2 = "\\RDPCredsStealerDLL.dll" ascii
		$s3 = "DLL Injected" ascii
		$s4 = "Code Injected" ascii
		$s5 = /(OpenProcess|VirtualAllocEx|CreateRemoteThread)\(\) failed:/ fullword ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}
