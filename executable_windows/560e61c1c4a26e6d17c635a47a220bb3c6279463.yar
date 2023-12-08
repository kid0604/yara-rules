rule APT_HAFNIUM_Forensic_Artefacts_Mar21_1
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		date = "2021-03-02"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "lsass.exe C:\\windows\\temp\\lsass" ascii wide fullword
		$s2 = "c:\\ProgramData\\it.zip" ascii wide fullword
		$s3 = "powercat.ps1'); powercat -c" ascii wide fullword

	condition:
		1 of them
}
