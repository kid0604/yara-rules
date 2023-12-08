rule MAL_ELF_LNX_Mirai_Oct10_1
{
	meta:
		description = "Detects ELF Mirai variant"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-10-27"
		modified = "2023-01-27"
		hash1 = "3be2d250a3922aa3f784e232ce13135f587ac713b55da72ef844d64a508ddcfe"
		os = "linux"
		filetype = "executable"

	strings:
		$x1 = " -r /vi/mips.bushido; "
		$x2 = "/bin/busybox chmod 777 * /tmp/" ascii
		$s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
		$s2 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
		$s3 = "POST /cdn-cgi/" ascii

	condition:
		uint16(0)==0x457f and filesize <200KB and ((1 of ($x*) and 1 of ($s*)) or all of ($x*))
}
