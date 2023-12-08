import "pe"

rule T5000Strings : T5000 Family
{
	meta:
		description = "T5000 Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-26"
		os = "windows"
		filetype = "script"

	strings:
		$ = "_tmpR.vbs"
		$ = "_tmpg.vbs"
		$ = "Dtl.dat" wide ascii
		$ = "3C6FB3CA-69B1-454f-8B2F-BD157762810E"
		$ = "EED5CA6C-9958-4611-B7A7-1238F2E1B17E"
		$ = "8A8FF8AD-D1DE-4cef-B87C-82627677662E"
		$ = "43EE34A9-9063-4d2c-AACD-F5C62B849089"
		$ = "A8859547-C62D-4e8b-A82D-BE1479C684C9"
		$ = "A59CF429-D0DD-4207-88A1-04090680F714"
		$ = "utd_CE31" wide ascii
		$ = "f:\\Project\\T5000\\Src\\Target\\1 KjetDll.pdb"
		$ = "l:\\MyProject\\Vc 7.1\\T5000\\T5000Ver1.28\\Target\\4 CaptureDLL.pdb"
		$ = "f:\\Project\\T5000\\Src\\Target\\4 CaptureDLL.pdb"
		$ = "E:\\VS2010\\xPlat2\\Release\\InstRes32.pdb"

	condition:
		any of them
}
