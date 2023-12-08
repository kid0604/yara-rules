import "pe"

rule Greenbug_Malware_Nov17_1
{
	meta:
		description = "Detects Greenbug Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/greenbug/"
		date = "2017-11-26"
		hash1 = "6e55e161dc9ace3076640a36ef4a8819bb85c6d5e88d8e852088478f79cf3b7c"
		hash2 = "a9f1375da973b229eb649dc3c07484ae7513032b79665efe78c0e55a6e716821"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "AgentV2.exe  -c  SampleDomain.com" fullword ascii
		$x2 = ".ntpupdateserver.com" fullword ascii
		$x3 = "Content-Disposition: form-data; name=\"file\"; filename=\"a.a\"" fullword ascii
		$x4 = "a67d0db885a3432576548a2a03707334" fullword ascii
		$x5 = "a67d0db8a2a173347654432503702aa3" fullword ascii
		$x6 = "!!! can not create output file !!!" fullword ascii
		$s1 = "\\runlog*" ascii
		$s2 = "can not specify username!!" fullword ascii
		$s3 = "Agent can not be configured" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (pe.imphash()=="58ba44f7ff5436a603fec3df97d815ea" or pe.imphash()=="538805ecd776b9a42e71aebf94fde1b1" or 1 of ($x*) or 3 of them )
}
