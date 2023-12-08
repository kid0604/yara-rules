import "pe"

rule OilRig_ISMAgent_Campaign_Samples3
{
	meta:
		description = "Detects OilRig malware from Unit 42 report in October 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/JQVfFP"
		date = "2017-10-18"
		hash1 = "a9f1375da973b229eb649dc3c07484ae7513032b79665efe78c0e55a6e716821"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd /c schtasks /query /tn TimeUpdate > NUL 2>&1" ascii
		$x2 = "schtasks /create /sc minute /mo 0002 /tn TimeUpdate /tr" fullword ascii
		$x3 = "-c  SampleDomain.com -m scheduleminutes" fullword ascii
		$x4 = ".ntpupdateserver.com" fullword ascii
		$x5 = ".msoffice365update.com" fullword ascii
		$s1 = "out.exe" fullword ascii
		$s2 = "\\Win32Project1\\Release\\Win32Project1.pdb" ascii
		$s3 = "C:\\windows\\system32\\cmd.exe /c (" ascii
		$s4 = "Content-Disposition: form-data; name=\"file\"; filename=\"a.a\"" fullword ascii
		$s5 = "Agent configured successfully" fullword ascii
		$s6 = "\\runlog*" ascii
		$s7 = "can not specify username!!" fullword ascii
		$s8 = "Agent can not be configured" fullword ascii
		$s9 = "%08lX%04hX%04hX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX" fullword ascii
		$s10 = "!!! can not create output file !!!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (pe.imphash()=="538805ecd776b9a42e71aebf94fde1b1" or pe.imphash()=="861ac226fbe8c99a2c43ff451e95da97" or (1 of ($x*) or 3 of them ))
}
