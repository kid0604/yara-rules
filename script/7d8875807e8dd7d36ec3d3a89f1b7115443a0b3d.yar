rule EXPL_Log4j_CVE_2021_44228_JAVA_Exception_Dec21_1
{
	meta:
		description = "Detects exceptions found in server logs that indicate an exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b"
		date = "2021-12-12"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$xa1 = "header with value of BadAttributeValueException: "
		$sa1 = ".log4j.core.net.JndiManager.lookup(JndiManager"
		$sa2 = "Error looking up JNDI resource"

	condition:
		$xa1 or all of ($sa*)
}
