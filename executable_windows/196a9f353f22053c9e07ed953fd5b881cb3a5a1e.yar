import "pe"

rule Daserf_Nov1_BronzeButler
{
	meta:
		description = "Detects Daserf malware used by Bronze Butler"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/ffeCfd"
		date = "2017-11-08"
		hash1 = "5ede6f93f26ccd6de2f93c9bd0f834279df5f5cfe3457915fae24a3aec46961b"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "mstmp1845234.exe" fullword ascii
		$x2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; SV1)" fullword ascii
		$x3 = "Mozilla/4.0 (compatible; MSIE 11.0; Windows NT 6.1; SV1)" fullword ascii
		$s1 = "Content-Type: */*" fullword ascii
		$s2 = "ProxyEnable" ascii fullword
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii fullword
		$s4 = "iexplore.exe" ascii fullword
		$s5 = "\\SOFTWARE\\Microsoft\\Windows\\Cu" ascii
		$s6 = "rrentVersion\\Internet Settings" fullword ascii
		$s7 = "ws\\CurrentVersion\\Inter" fullword ascii
		$s8 = "Documents an" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and (1 of ($x*) or 5 of them )
}
