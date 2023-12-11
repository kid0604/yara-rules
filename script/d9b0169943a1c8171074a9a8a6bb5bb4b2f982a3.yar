rule CobaltStrike_Resources_Template_Sct_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.sct signature for versions v3.3 to v4.x"
		hash = "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "script"

	strings:
		$scriptletstart = "<scriptlet>" nocase
		$registration = "<registration progid=" nocase
		$classid = "classid=" nocase
		$scriptlang = "<script language=\"vbscript\">" nocase
		$cdata = "<![CDATA["
		$scriptend = "</script>" nocase
		$antiregistration = "</registration>" nocase
		$scriptletend = "</scriptlet>"

	condition:
		all of them and @scriptletstart[1]<@registration[1] and @registration[1]<@classid[1] and @classid[1]<@scriptlang[1] and @scriptlang[1]<@cdata[1]
}
