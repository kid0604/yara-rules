import "pe"

rule Dropper_HTA_WildChild_1
{
	meta:
		description = "This rule looks for strings present in unobfuscated HTAs generated by the WildChild builder."
		md5 = "3e61ca5057633459e96897f79970a46d"
		rev = 5
		author = "FireEye"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "processpath" ascii wide
		$s2 = "v4.0.30319" ascii wide
		$s3 = "v2.0.50727" ascii wide
		$s4 = "COMPLUS_Version" ascii wide
		$s5 = "FromBase64Transform" ascii wide
		$s6 = "MemoryStream" ascii wide
		$s7 = "entry_class" ascii wide
		$s8 = "DynamicInvoke" ascii wide
		$s9 = "Sendoff" ascii wide
		$script_header = "<script language=" ascii wide

	condition:
		$script_header at 0 and all of ($s*)
}
