rule MAL_RANSOM_SH_ESXi_Attacks_Feb23_1
{
	meta:
		description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers - file encrypt.sh"
		author = "Florian Roth"
		reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
		date = "2023-02-04"
		score = 85
		hash1 = "10c3b6b03a9bf105d264a8e7f30dcab0a6c59a414529b0af0a6bd9f1d2984459"
		os = "linux"
		filetype = "script"

	strings:
		$x1 = "/bin/find / -name *.log -exec /bin/rm -rf {} \\;" ascii fullword
		$x2 = "/bin/touch -r /etc/vmware/rhttpproxy/config.xml /bin/hostd-probe.sh" ascii fullword
		$x3 = "grep encrypt | /bin/grep -v grep | /bin/wc -l)" ascii fullword
		$s1 = "## ENCRYPT" ascii fullword
		$s2 = "/bin/find / -name *.log -exec /bin" ascii fullword

	condition:
		uint16(0)==0x2123 and filesize <10KB and (1 of ($x*) or 2 of them ) or 3 of them
}
