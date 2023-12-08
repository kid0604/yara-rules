rule INDICATOR_TOOL_PWS_Rubeus
{
	meta:
		author = "ditekSHen"
		description = "Detects Rubeus kerberos defensive/offensive toolset"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" fullword wide
		$s2 = "(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))" fullword wide
		$s3 = "rc4opsec" fullword wide
		$s4 = "pwdlastset" fullword wide
		$s5 = "LsaEnumerateLogonSessions" fullword ascii
		$s6 = "extractKerberoastHash" fullword ascii
		$s7 = "ComputeAllKerberosPasswordHashes" fullword ascii
		$s8 = "kerberoastDomain" fullword ascii
		$s9 = "GetUsernamePasswordTGT" fullword ascii
		$s10 = "WriteUserPasswordToFile" fullword ascii

	condition:
		uint16(0)==0x5a4d and 8 of them
}
