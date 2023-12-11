rule GetUserSPNs_VBS
{
	meta:
		description = "Auto-generated rule - file GetUserSPNs.vbs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "8dcb568d475fd8a0557e70ca88a262b7c06d0f42835c855b52e059c0f5ce9237"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Wscript.Echo \"User Logon: \" & oRecordset.Fields(\"samAccountName\")" fullword ascii
		$s2 = "Wscript.Echo \" USAGE:        \" & WScript.ScriptName & \" SpnToFind [GC Servername or Forestname]\"" fullword ascii
		$s3 = "strADOQuery = \"<\" + strGCPath + \">;(&(!objectClass=computer)(servicePrincipalName=*));\" & _" fullword ascii

	condition:
		2 of them
}
