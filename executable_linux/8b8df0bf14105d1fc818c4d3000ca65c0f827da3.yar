import "pe"

rule MALWARE_Linux_GetShell
{
	meta:
		author = "ditekSHen"
		description = "Detect GetShell Linux backdoor"
		clamav1 = "MALWARE.Linux.Trojan.GetShell"
		os = "linux"
		filetype = "executable"

	strings:
		$x1 = "cat <(echo '@reboot echo socks5_backconnect" ascii
		$x2 = "(cd  && )') <(sed '/socks5_backconnect" ascii
		$s1 = "cat <(echo '@" ascii
		$s2 = "(cd  && )') <(sed '" ascii
		$s3 = "PORT1:" ascii
		$s4 = "HOST1:" ascii
		$s5 = "queryheader" ascii
		$s6 = "qsectionpost" ascii
		$s7 = "packedip" ascii
		$s8 = "copydata" ascii
		$s9 = "synsend" ascii
		$s10 = "bc_connect" ascii

	condition:
		uint16(0)==0x457f and (( all of ($x*) and 1 of ($s*)) or 5 of ($s*))
}
