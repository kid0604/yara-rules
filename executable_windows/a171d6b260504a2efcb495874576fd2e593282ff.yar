import "pe"

rule HvS_APT37_cred_tool
{
	meta:
		description = "Unknown cred tool used by APT37"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Markus Poelloth"
		date = "2020-12-15"
		reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
		$s2 = "Domain Login" fullword ascii
		$s3 = "IEShims_GetOriginatingThreadContext" fullword ascii
		$s4 = " Type Descriptor'" fullword ascii
		$s5 = "User: %s" fullword ascii
		$s6 = "Pass: %s" fullword ascii
		$s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s8 = "E@c:\\u" fullword ascii

	condition:
		filesize <500KB and 7 of them
}
