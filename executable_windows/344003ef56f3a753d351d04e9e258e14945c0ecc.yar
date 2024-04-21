import "pe"

rule informational_AdFind_AD_Recon_and_Admin_Tool
{
	meta:
		description = "files - AdFind.exe"
		author = "TheDFIRReport"
		date = "2021-07-25"
		hash1 = "b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "   -sc dumpugcinfo         Dump info for users/computers that have used UGC" fullword ascii
		$s2 = "   -sc computers_pwdnotreqd Dump computers set with password not required." fullword ascii
		$s3 = "   -sc computers_inactive  Dump computers that are disabled or password last set" fullword ascii
		$s4 = "   -sc computers_active    Dump computers that are enabled and password last" fullword ascii
		$s5 = "   -sc ridpool             Dump Decoded Rid Pool Info" fullword ascii
		$s6 = "      Get top 10 quota users in decoded format" fullword ascii
		$s7 = "   -po           Print options. This switch will dump to the command line" fullword ascii
		$s8 = "ERROR: Couldn't properly encode password - " fullword ascii
		$s9 = "   -sc users_accexpired    Dump accounts that are expired (NOT password expiration)." fullword ascii
		$s10 = "   -sc users_disabled      Dump disabled users." fullword ascii
		$s11 = "   -sc users_pwdnotreqd    Dump users set with password not required." fullword ascii
		$s12 = "   -sc users_noexpire      Dump non-expiring users." fullword ascii
		$s13 = "    adfind -default -rb ou=MyUsers -objfilefolder c:\\temp\\ad_out" fullword ascii
		$s14 = "      Dump all Exchange objects and their SMTP proxyaddresses" fullword ascii
		$s15 = "WLDAP32.DLL" fullword ascii
		$s16 = "AdFind.exe" fullword ascii
		$s17 = "                   duration attributes that will be decoded by the -tdc* switches." fullword ascii
		$s18 = "   -int8time- xx Remove attribute(s) from list to be decoded as int8. Semicolon delimited." fullword ascii
		$s19 = "replTopologyStayOfExecution" fullword ascii
		$s20 = "%s: [%s] Error 0x%0x (%d) - %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and 8 of them
}
