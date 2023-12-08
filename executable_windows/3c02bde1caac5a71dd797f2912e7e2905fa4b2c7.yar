import "pe"

rule Suckfly_Nidiran_Gen_2
{
	meta:
		description = "Detects Suckfly Nidiran Trojan"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
		date = "2018-01-28"
		hash1 = "b53a316a03b46758cb128e5045dab2717cb36e7b5eb1863ce2524d4f69bc2cab"
		hash2 = "eaee2bf83cf90d35dab8a4711f7a5f2ebf9741007668f3746995f4564046fbdf"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "WorkDll.dll" fullword ascii
		$x2 = "%userprofile%\\Security Center\\secriter.dll" fullword ascii
		$s1 = "DLL_PROCESS_ATTACH is called" fullword ascii
		$s2 = "Support Security Accounts Manager For Microsoft Windows.If this service is stopped, any services that depended on it will fail t" ascii
		$s3 = "before CreateRemoteThread" fullword ascii
		$s4 = "CreateRemoteThread Succ" fullword ascii
		$s5 = "Microsoft Security Accounts Manager" fullword ascii
		$s6 = "DoRunRemote" fullword ascii
		$s7 = "AutoRunFun" fullword ascii
		$s8 = "ServiceMain is called" fullword ascii
		$s9 = "DllRegisterServer is called" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (1 of ($x*) or 4 of them )
}
