rule INDICATOR_TOOL_SharpLDAP
{
	meta:
		author = "ditekSHen"
		description = "Detects SharpLDAP tool written in C# that aims to do enumeration via LDAP queries"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "SharpLDAP" ascii wide
		$x2 = "SharpLDAP.pdb" ascii
		$s1 = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" wide
		$s2 = "(&(servicePrincipalName=*))" wide
		$s3 = "/Enumerating (Domain|Enterprise|Organizational|Service|Members|Users|Computers)/" wide
		$s4 = "ListMembers" fullword ascii
		$s5 = "GroupMembers" fullword ascii
		$s6 = "get_SamAccountName" fullword ascii

	condition:
		uint16(0)==0x5a4d and ((1 of ($x*) and 4 of ($s*)) or (5 of ($s*)))
}
