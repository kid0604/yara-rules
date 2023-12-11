rule ProjectM_CrimsonDownloader
{
	meta:
		description = "Detects ProjectM Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
		date = "2016-03-26"
		hash = "dc8bd60695070152c94cbeb5f61eca6e4309b8966f1aa9fdc2dd0ab754ad3e4c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "E:\\Projects\\m_project\\main\\mj shoaib"
		$s1 = "\\obj\\x86\\Debug\\secure_scan.pdb" ascii
		$s2 = "secure_scan.exe" fullword wide
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|mswall" fullword wide
		$s4 = "secure_scan|mswall" fullword wide
		$s5 = "[Microsoft-Security-Essentials]" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and $x1) or ( all of them )
}
