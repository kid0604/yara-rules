rule App_Web_vjloy3pa
{
	meta:
		description = "9893_files - file App_Web_vjloy3pa.dll"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
		date = "2022-03-21"
		hash1 = "faa315db522d8ce597ac0aa957bf5bde31d91de94e68d5aefac4e3e2c11aa970"
		os = "windows"
		filetype = "executable"

	strings:
		$x2 = "hSystem.ComponentModel.DataAnnotations, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
		$s3 = "MSystem.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
		$s4 = "RSystem.Xml.Linq, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
		$s5 = "ZSystem.ServiceModel.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
		$s6 = "YSystem.Web.DynamicData, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
		$s7 = "XSystem.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
		$s8 = "VSystem.Web.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
		$s9 = "MSystem.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
		$s10 = "WSystem.Configuration, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
		$s11 = "`System.Data.DataSetExtensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
		$s12 = "NSystem.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
		$s13 = "ZSystem.WorkflowServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
		$s14 = "WSystem.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
		$s15 = "aSystem.ServiceModel.Activation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
		$s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide
		$s17 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide
		$s18 = "aSystem.Web.ApplicationServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
		$s19 = "\\System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
		$s20 = "SMicrosoft.CSharp, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of ($x*) and 4 of them
}
