rule JavaDeploymentToolkit
{
	meta:
		ref = "CVE-2010-0887"
		impact = 7
		author = "@d3t0n4t0r"
		description = "Yara rule for detecting Java Deployment Toolkit CVE-2010-0887"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$cve20100887_1 = "CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" nocase fullword
		$cve20100887_2 = "document.createElement(\"OBJECT\")" nocase fullword
		$cve20100887_3 = "application/npruntime-scriptable-plugin;deploymenttoolkit" nocase fullword
		$cve20100887_4 = "application/java-deployment-toolkit" nocase fullword
		$cve20100887_5 = "document.body.appendChild(" nocase fullword
		$cve20100887_6 = "launch("
		$cve20100887_7 = "-J-jar -J" nocase fullword

	condition:
		3 of them
}
