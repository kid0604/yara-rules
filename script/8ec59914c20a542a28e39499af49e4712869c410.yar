rule APT_PY_ESXi_Backdoor_Dec22
{
	meta:
		description = "Detects Python backdoor found on ESXi servers"
		author = "Florian Roth"
		reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
		date = "2022-12-14"
		score = 85
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "cmd = str(base64.b64decode(encoded_cmd), " ascii
		$x2 = "sh -i 2>&1 | nc %s %s > /tmp/" ascii

	condition:
		filesize <10KB and 1 of them or all of them
}
