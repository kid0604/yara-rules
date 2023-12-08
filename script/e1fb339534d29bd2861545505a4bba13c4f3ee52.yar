rule WEBSHELL_CVE_2021_27065_Webshells
{
	meta:
		description = "Detects web shells dropped by CVE-2021-27065. All actors, not specific to HAFNIUM. TLP:WHITE"
		author = "Joe Hannon, Microsoft Threat Intelligence Center (MSTIC)"
		date = "2021-03-05"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$script1 = "script language" ascii wide nocase
		$script2 = "page language" ascii wide nocase
		$script3 = "runat=\"server\"" ascii wide nocase
		$script4 = "/script" ascii wide nocase
		$externalurl = "externalurl" ascii wide nocase
		$internalurl = "internalurl" ascii wide nocase
		$internalauthenticationmethods = "internalauthenticationmethods" ascii wide nocase
		$extendedprotectiontokenchecking = "extendedprotectiontokenchecking" ascii wide nocase

	condition:
		filesize <50KB and any of ($script*) and ($externalurl or $internalurl) and $internalauthenticationmethods and $extendedprotectiontokenchecking
}
