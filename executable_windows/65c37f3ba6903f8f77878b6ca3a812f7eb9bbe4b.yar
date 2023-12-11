import "pe"

rule APT_Webshell_SUPERNOVA_2
{
	meta:
		author = "FireEye"
		description = "This rule is looking for specific strings related to SUPERNOVA. SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args)."
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		date = "2020-12-14"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$dynamic = "DynamicRun"
		$solar = "Solarwinds" nocase
		$string1 = "codes"
		$string2 = "clazz"
		$string3 = "method"
		$string4 = "args"

	condition:
		uint16(0)==0x5a4d and uint32( uint32(0x3C))==0x00004550 and filesize <10KB and 3 of ($string*) and $dynamic and $solar
}
