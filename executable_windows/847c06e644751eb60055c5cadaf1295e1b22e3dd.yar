rule APT_APT29_wellmess_dotnet_unique_strings
{
	meta:
		description = "Rule to detect WellMess .NET samples based on unique strings and function/variable names"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "2285a264ffab59ab5a1eb4e2b9bcab9baf26750b6c551ee3094af56a4442ac41"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "HealthInterval" wide
		$s2 = "Hello from Proxy" wide
		$s3 = "Start bot:" wide
		$s4 = "FromNormalToBase64" ascii
		$s5 = "FromBase64ToNormal" ascii
		$s6 = "WellMess" ascii

	condition:
		uint16(0)==0x5a4d and uint16( uint16(0x3c))==0x4550 and 3 of them
}
