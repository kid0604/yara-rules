import "pe"

rule IMPLANT_8_v1_alt_1
{
	meta:
		description = "HAMMERTOSS / HammerDuke Implant by APT29"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 65
		os = "windows"
		filetype = "executable"

	strings:
		$DOTNET = "mscorlib" ascii
		$REF_URL = "https://www.google.com/url?sa=" wide
		$REF_var_1 = "&rct=" wide
		$REF_var_2 = "&q=&esrc=" wide
		$REF_var_3 = "&source=" wide
		$REF_var_4 = "&cd=" wide
		$REF_var_5 = "&ved=" wide
		$REF_var_6 = "&url=" wide
		$REF_var_7 = "&ei=" wide
		$REF_var_8 = "&usg=" wide
		$REF_var_9 = "&bvm=" wide

	condition:
		( uint16(0)==0x5A4D) and ($DOTNET) and ($REF_URL) and (3 of ($REF_var*))
}
