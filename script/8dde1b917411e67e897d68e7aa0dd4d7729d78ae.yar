rule APT_SH_ESXi_Backdoor_Dec22
{
	meta:
		description = "Detects malicious script found on ESXi servers"
		author = "Florian Roth"
		reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
		date = "2022-12-14"
		score = 75
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "mv /bin/hostd-probe.sh /bin/hostd-probe.sh.1" ascii fullword
		$x2 = "/bin/nohup /bin/python -u /store/packages/vmtools.py" ascii
		$x3 = "/bin/rm /bin/hostd-probe.sh.1"

	condition:
		filesize <10KB and 1 of them
}
